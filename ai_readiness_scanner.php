<?php

/**
 * AI-Readiness Bulk Scanner
 * ---------------------------------------------------------------------------
 * Grades how well a website can be read by generative search engines
 * (ChatGPT search, Perplexity, Google AI Overviews, Claude). No browser,
 * no API key, no quota — a handful of HTTP fetches + HTML parsing on the
 * homepage. Produces:
 *
 *   - a self-contained HTML report   (ai_readiness_report.html)
 *   - a CSV export                   (ai_readiness_report.csv)
 *   - a console summary
 *
 * Usage:
 *   php ai_readiness_scanner.php --url=https://example.com [options]
 *
 * Options:
 *   --url=URL            Site to check (required)
 *   --output=FILE        HTML report path (default ai_readiness_report.html)
 *   --csv=FILE           CSV export path  (default ai_readiness_report.csv)
 *   --max-urls=N         Accepted for interface parity; the check is
 *                        homepage-level, so N is not used (default 1)
 *   --user-agent=STR     Override the fetch User-Agent
 *   --timeout=S          Per-request cURL timeout in seconds (default 15)
 *   --max-redirects=N    Redirects followed per fetch (default 5)
 *   --insecure           Skip TLS certificate verification
 *   --allow-private      Do NOT block redirects to private/reserved IPs
 *                        (off by default — the built-in SSRF guard)
 *   --help               Show this help
 *
 * Signals & points (sum to 100):
 *   AI crawler access   30   robots.txt allows GPTBot/ClaudeBot/PerplexityBot/…
 *   Structured data     20   JSON-LD (10) + meta description (4) + OG (3) + title (3)
 *   Server-rendered     15   main text present in raw HTML (no JS needed)
 *   Semantic HTML       15   single <h1> (6) + <main>/<article> (5) + headings (4)
 *   Discoverability     10   sitemap (5) + llms.txt (5)
 *   Performance (TTFB)  10   fast Time to First Byte for live AI retrieval
 *
 * MIT licensed. Plain PHP (curl, dom).
 */

const VERSION = '1.0.0';
const DEFAULT_UA = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36';
const RENDERED_TEXT_TARGET = 1200; // visible chars in raw HTML for full server-rendered points

/** Major AI/LLM crawlers. Blocking one = invisible to that assistant. */
const AI_BOTS = [
    'GPTBot',            // OpenAI training
    'OAI-SearchBot',     // ChatGPT search
    'ChatGPT-User',      // ChatGPT live browsing
    'ClaudeBot',         // Anthropic training
    'Claude-SearchBot',  // Claude search
    'PerplexityBot',     // Perplexity index
    'Google-Extended',   // Gemini / AI Overviews
    'CCBot',             // Common Crawl (feeds many models)
    'Applebot-Extended', // Apple Intelligence
];

/** Points per signal group (must sum to 100). */
const POINTS = [
    'crawler_access' => 30,
    'structured_data' => 20,  // 10 + 4 + 3 + 3
    'rendered_content' => 15,
    'semantic_html' => 15,    // 6 + 5 + 4
    'discoverability' => 10,  // 5 + 5
    'performance' => 10,      // TTFB (Time to First Byte)
];

// TTFB scoring band: full marks at/under FULL, zero at/over ZERO, linear between.
// Live AI retrieval (Perplexity, browsing assistants) fetches under a tight
// latency budget — a slow first byte can time out and drop you from the answer.
const TTFB_FULL_MS = 500;
const TTFB_ZERO_MS = 2000;
const TTFB_PASS_MS = 800; // green ≤ this; "improve" above

// ── Args ────────────────────────────────────────────────────────────────────
function parse_args(): array
{
    $defaults = [
        'url' => null,
        'output' => 'ai_readiness_report.html',
        'csv' => 'ai_readiness_report.csv',
        'max-urls' => 1,
        'user-agent' => DEFAULT_UA,
        'timeout' => 15,
        'max-redirects' => 5,
        'verify-tls' => true,
        'guard-private' => true,
    ];

    $opts = getopt('', [
        'url:', 'output:', 'csv:', 'max-urls:', 'user-agent:', 'timeout:',
        'max-redirects:', 'insecure', 'allow-private', 'help',
    ]);

    if (isset($opts['help']) || empty($opts['url'])) {
        fwrite(STDOUT, <<<HELP

AI-Readiness Bulk Scanner — is your site readable by AI search engines?

Usage:
  php ai_readiness_scanner.php --url=URL [options]

Options:
  --url=URL            Site to check (required)
  --output=FILE        HTML report path (default ai_readiness_report.html)
  --csv=FILE           CSV export path  (default ai_readiness_report.csv)
  --max-urls=N         Interface parity only; the check is homepage-level
  --user-agent=STR     Override the fetch User-Agent
  --timeout=S          Per-request cURL timeout in seconds (default 15)
  --max-redirects=N    Redirects followed per fetch (default 5)
  --insecure           Skip TLS certificate verification
  --allow-private      Disable the built-in SSRF guard (allow private IPs)
  --help               Show this help

Example:
  php ai_readiness_scanner.php --url=https://example.com

HELP);
        exit(empty($opts['url']) && ! isset($opts['help']) ? 1 : 0);
    }

    $args = $defaults;
    $args['url'] = (string) $opts['url'];
    if (! preg_match('#^https?://#i', $args['url'])) {
        $args['url'] = 'https://'.$args['url'];
    }
    foreach (['output', 'csv', 'user-agent'] as $k) {
        if (isset($opts[$k])) {
            $args[$k] = (string) $opts[$k];
        }
    }
    $args['timeout'] = max(1, (int) ($opts['timeout'] ?? $defaults['timeout']));
    $args['max-redirects'] = max(0, (int) ($opts['max-redirects'] ?? $defaults['max-redirects']));
    $args['verify-tls'] = ! isset($opts['insecure']);
    $args['guard-private'] = ! isset($opts['allow-private']);

    return $args;
}

// ── HTTP (manual redirect following with an SSRF guard) ───────────────────────

/** True when the host resolves only to public IPs (and isn't localhost/intranet). */
function host_is_public(?string $host): bool
{
    if (! $host) {
        return false;
    }
    $host = strtolower(rtrim($host, '.'));
    $literal = trim($host, '[]');
    if (filter_var($literal, FILTER_VALIDATE_IP) !== false) {
        return filter_var($literal, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) !== false;
    }
    if (
        $host === 'localhost'
        || str_ends_with($host, '.localhost')
        || str_ends_with($host, '.local')
        || str_ends_with($host, '.internal')
        || ! str_contains($host, '.')
    ) {
        return false;
    }
    $ips = [];
    foreach (@dns_get_record($host, DNS_A | DNS_AAAA) ?: [] as $r) {
        if (isset($r['ip'])) {
            $ips[] = $r['ip'];
        }
        if (isset($r['ipv6'])) {
            $ips[] = $r['ipv6'];
        }
    }
    if ($ips === []) {
        return false;
    }
    foreach ($ips as $ip) {
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) === false) {
            return false;
        }
    }

    return true;
}

/** Resolve a (possibly relative) Location against the current URL. */
function absolute_url(string $base, string $location): string
{
    if (preg_match('#^https?://#i', $location)) {
        return $location;
    }
    $p = parse_url($base);
    $origin = ($p['scheme'] ?? 'https').'://'.($p['host'] ?? '').(isset($p['port']) ? ':'.$p['port'] : '');
    if (str_starts_with($location, '/')) {
        return $origin.$location;
    }
    $dir = isset($p['path']) ? preg_replace('#/[^/]*$#', '/', $p['path']) : '/';

    return $origin.$dir.$location;
}

/**
 * GET with the given UA. Follows redirects manually, re-checking the target
 * host on every hop so a 3xx can't point the fetch at an internal address.
 *
 * @return array{body: ?string, status: int, blocked: bool, ttfb: ?float}
 *   ttfb is the final response's Time to First Byte in seconds (null if unfetched).
 */
function http_get(string $url, array $args): array
{
    $current = $url;
    for ($i = 0; $i <= $args['max-redirects']; $i++) {
        if ($args['guard-private'] && ! host_is_public(parse_url($current, PHP_URL_HOST))) {
            return ['body' => null, 'status' => 0, 'blocked' => true, 'ttfb' => null];
        }
        $ch = curl_init($current);
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_HEADER => true,
            CURLOPT_TIMEOUT => $args['timeout'],
            CURLOPT_CONNECTTIMEOUT => 10,
            CURLOPT_USERAGENT => $args['user-agent'],
            CURLOPT_PROTOCOLS => CURLPROTO_HTTP | CURLPROTO_HTTPS,
            CURLOPT_SSL_VERIFYPEER => $args['verify-tls'],
            CURLOPT_SSL_VERIFYHOST => $args['verify-tls'] ? 2 : 0,
            CURLOPT_ENCODING => '',
        ]);
        $resp = curl_exec($ch);
        if ($resp === false) {
            return ['body' => null, 'status' => 0, 'blocked' => false, 'ttfb' => null];
        }
        $headerSize = curl_getinfo($ch, CURLINFO_HEADER_SIZE);
        $code = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $ttfb = (float) curl_getinfo($ch, CURLINFO_STARTTRANSFER_TIME);
        $headers = substr($resp, 0, $headerSize);
        $body = substr($resp, $headerSize);

        if ($code >= 300 && $code < 400 && preg_match('/^location:\s*(.+)$/im', $headers, $m)) {
            $current = absolute_url($current, trim($m[1]));

            continue;
        }

        return ['body' => $body, 'status' => $code, 'blocked' => false, 'ttfb' => $ttfb];
    }

    return ['body' => null, 'status' => 0, 'blocked' => false, 'ttfb' => null];
}

/**
 * Median homepage TTFB in milliseconds over up to $samples fresh fetches.
 * Seeded with the homepage sample already taken, so it only adds $samples-1
 * requests. Breaks early if a fetch fails (don't hammer a struggling host).
 * Returns 0 when nothing could be measured.
 */
function measure_ttfb(string $url, array $args, float $firstSample, int $samples = 3): int
{
    $vals = [];
    if ($firstSample > 0) {
        $vals[] = $firstSample;
    }
    while (count($vals) < $samples) {
        $r = http_get($url, $args);
        if (($r['ttfb'] ?? 0) > 0 && $r['status'] >= 200 && $r['status'] < 400) {
            $vals[] = $r['ttfb'];
        } else {
            break;
        }
    }
    if ($vals === []) {
        return 0;
    }
    sort($vals);
    $mid = intdiv(count($vals), 2);
    $median = count($vals) % 2 === 1 ? $vals[$mid] : ($vals[$mid - 1] + $vals[$mid]) / 2;

    return (int) round($median * 1000);
}

function base_url(string $url): string
{
    $p = parse_url($url);
    $base = ($p['scheme'] ?? 'https').'://'.($p['host'] ?? '');

    return isset($p['port']) ? $base.':'.$p['port'] : $base;
}

// ── robots.txt ────────────────────────────────────────────────────────────────

/** @return array<string, list<string>> user-agent (lowercase) => Disallow paths */
function parse_robots(string $robots): array
{
    $groups = [];
    $agents = [];
    $expectingAgent = false;
    foreach (preg_split('/\r\n|\r|\n/', $robots) as $line) {
        $line = trim(preg_replace('/#.*$/', '', $line));
        if ($line === '' || ! str_contains($line, ':')) {
            continue;
        }
        [$field, $value] = array_map('trim', explode(':', $line, 2));
        $field = strtolower($field);
        if ($field === 'user-agent') {
            if (! $expectingAgent) {
                $agents = [];
            }
            $agents[] = strtolower($value);
            $groups[strtolower($value)] ??= [];
            $expectingAgent = true;
        } elseif ($field === 'disallow') {
            foreach ($agents as $a) {
                $groups[$a][] = $value;
            }
            $expectingAgent = false;
        } else {
            $expectingAgent = false;
        }
    }

    return $groups;
}

function is_bot_blocked(array $groups, string $bot): bool
{
    $rules = $groups[strtolower($bot)] ?? $groups['*'] ?? null;
    if ($rules === null) {
        return false;
    }
    foreach ($rules as $path) {
        if ($path === '/' || $path === '/*') {
            return true;
        }
    }

    return false;
}

/** Length of visible text in raw HTML (scripts/styles/tags stripped). */
function visible_text_length(string $html): int
{
    $stripped = preg_replace([
        '/<script\b[^>]*>.*?<\/script>/is',
        '/<style\b[^>]*>.*?<\/style>/is',
        '/<!--.*?-->/s',
        '/<[^>]+>/s',
    ], ' ', $html);

    return mb_strlen(trim(preg_replace('/\s+/', ' ', html_entity_decode($stripped ?? ''))));
}

// ── Analysis ──────────────────────────────────────────────────────────────────

/**
 * Run all signal detectors and return the scored rows.
 *
 * @return array{rows: list<array<string,mixed>>, score: int, error: ?string}
 */
function analyze(array $args): array
{
    $url = $args['url'];
    $base = base_url($url);

    $home = http_get($url, $args);
    if ($home['body'] === null || $home['status'] < 200 || $home['status'] >= 400) {
        $why = $home['blocked'] ? 'homepage redirects to a non-public host' : "could not fetch (status {$home['status']})";

        return ['rows' => [], 'score' => 0, 'error' => "{$url}: {$why}"];
    }
    $html = $home['body'];

    // Time to First Byte — median of a few homepage fetches (reuses $home's sample).
    $ttfbMs = measure_ttfb($url, $args, $home['ttfb'] ?? 0.0);

    $robotsRes = http_get($base.'/robots.txt', $args);
    $robots = ($robotsRes['status'] >= 200 && $robotsRes['status'] < 300) ? (string) $robotsRes['body'] : '';
    $llms = http_get($base.'/llms.txt', $args);
    $hasLlms = $llms['status'] >= 200 && $llms['status'] < 300;

    $groups = parse_robots($robots);

    // 1. AI crawler access
    $blocked = array_values(array_filter(AI_BOTS, fn ($b) => is_bot_blocked($groups, $b)));
    $allowed = count(AI_BOTS) - count($blocked);
    $crawlerScore = (int) round(POINTS['crawler_access'] * ($allowed / max(1, count(AI_BOTS))));

    // 2. Structured data
    $hasJsonLd = (bool) preg_match('/<script[^>]+type=["\']application\/ld\+json["\']/i', $html);
    $hasMetaDesc = (bool) preg_match('/<meta[^>]+name=["\']description["\'][^>]+content=["\'][^"\']+["\']/i', $html);
    $hasOg = (bool) preg_match('/<meta[^>]+property=["\']og:[a-z]+["\']/i', $html);
    $hasTitle = (bool) preg_match('/<title[^>]*>\s*\S+/i', $html);

    // 3. Server-rendered content
    $chars = visible_text_length($html);
    $renderedScore = (int) round(POINTS['rendered_content'] * min(1.0, $chars / max(1, RENDERED_TEXT_TARGET)));
    $serverRendered = $chars >= RENDERED_TEXT_TARGET;

    // 4. Semantic HTML
    $h1 = preg_match_all('/<h1[\s>]/i', $html);
    $headings = preg_match_all('/<h[1-6][\s>]/i', $html);
    $hasMain = (bool) preg_match('/<(main|article)[\s>]/i', $html);

    // 5. Discoverability
    $hasSitemap = (bool) preg_match('/^\s*sitemap\s*:/im', $robots)
        || in_array(http_get($base.'/sitemap.xml', $args)['status'], range(200, 299), true)
        || in_array(http_get($base.'/sitemap_index.xml', $args)['status'], range(200, 299), true);

    // 6. Performance — TTFB as a live-retrieval latency gate
    $ttfbFraction = ($ttfbMs <= 0)
        ? 0.0
        : max(0.0, min(1.0, (TTFB_ZERO_MS - $ttfbMs) / (TTFB_ZERO_MS - TTFB_FULL_MS)));
    $ttfbScore = (int) round(POINTS['performance'] * $ttfbFraction);
    $ttfbPass = $ttfbMs > 0 && $ttfbMs <= TTFB_PASS_MS;

    $rows = [
        [
            'group' => 'crawler_access', 'key' => 'crawler_access', 'label' => 'AI crawler access',
            'score' => $crawlerScore, 'max' => POINTS['crawler_access'], 'pass' => $blocked === [],
            'detail' => $blocked === [] ? "All {$allowed} major AI crawlers allowed"
                : count($blocked)." blocked in robots.txt: ".implode(', ', $blocked),
            'meta' => "allowed={$allowed};total=".count(AI_BOTS).';blocked='.implode('|', $blocked),
        ],
        [
            'group' => 'structured_data', 'key' => 'json_ld', 'label' => 'Structured data (schema.org)',
            'score' => $hasJsonLd ? 10 : 0, 'max' => 10, 'pass' => $hasJsonLd,
            'detail' => $hasJsonLd ? 'JSON-LD present' : 'No JSON-LD structured data found',
            'meta' => 'has_json_ld='.(int) $hasJsonLd,
        ],
        [
            'group' => 'structured_data', 'key' => 'meta_description', 'label' => 'Meta description',
            'score' => $hasMetaDesc ? 4 : 0, 'max' => 4, 'pass' => $hasMetaDesc,
            'detail' => $hasMetaDesc ? 'Present' : 'Missing', 'meta' => 'has_meta_description='.(int) $hasMetaDesc,
        ],
        [
            'group' => 'structured_data', 'key' => 'open_graph', 'label' => 'Open Graph tags',
            'score' => $hasOg ? 3 : 0, 'max' => 3, 'pass' => $hasOg,
            'detail' => $hasOg ? 'Present' : 'Missing', 'meta' => 'has_open_graph='.(int) $hasOg,
        ],
        [
            'group' => 'structured_data', 'key' => 'title', 'label' => 'Page title',
            'score' => $hasTitle ? 3 : 0, 'max' => 3, 'pass' => $hasTitle,
            'detail' => $hasTitle ? 'Present' : 'Missing', 'meta' => 'has_title='.(int) $hasTitle,
        ],
        [
            'group' => 'rendered_content', 'key' => 'server_rendered', 'label' => 'Server-rendered content',
            'score' => $renderedScore, 'max' => POINTS['rendered_content'], 'pass' => $serverRendered,
            'detail' => $serverRendered ? "~{$chars} chars of text in raw HTML"
                : "Only ~{$chars} chars in raw HTML — content may need JavaScript",
            'meta' => 'server_rendered='.(int) $serverRendered.";chars={$chars}",
        ],
        [
            'group' => 'semantic_html', 'key' => 'h1', 'label' => 'Single, clear <h1>',
            'score' => $h1 === 1 ? 6 : 0, 'max' => 6, 'pass' => $h1 === 1,
            'detail' => $h1 === 1 ? 'Exactly one <h1>' : "{$h1} <h1> elements", 'meta' => "h1_count={$h1}",
        ],
        [
            'group' => 'semantic_html', 'key' => 'landmarks', 'label' => 'Semantic landmarks',
            'score' => $hasMain ? 5 : 0, 'max' => 5, 'pass' => $hasMain,
            'detail' => $hasMain ? '<main>/<article> present' : 'No <main>/<article>',
            'meta' => 'has_main='.(int) $hasMain,
        ],
        [
            'group' => 'semantic_html', 'key' => 'headings', 'label' => 'Heading structure',
            'score' => $headings >= 3 ? 4 : 0, 'max' => 4, 'pass' => $headings >= 3,
            'detail' => "{$headings} headings", 'meta' => "heading_count={$headings}",
        ],
        [
            'group' => 'discoverability', 'key' => 'sitemap', 'label' => 'Sitemap',
            'score' => $hasSitemap ? 5 : 0, 'max' => 5, 'pass' => $hasSitemap,
            'detail' => $hasSitemap ? 'Discoverable' : 'None found', 'meta' => 'has_sitemap='.(int) $hasSitemap,
        ],
        [
            'group' => 'discoverability', 'key' => 'llms_txt', 'label' => 'llms.txt',
            'score' => $hasLlms ? 5 : 0, 'max' => 5, 'pass' => $hasLlms,
            'detail' => $hasLlms ? 'Present' : 'Not present (optional, emerging)',
            'meta' => 'has_llms_txt='.(int) $hasLlms,
        ],
        [
            'group' => 'performance', 'key' => 'ttfb', 'label' => 'Time to First Byte',
            'score' => $ttfbScore, 'max' => POINTS['performance'], 'pass' => $ttfbPass,
            'detail' => match (true) {
                $ttfbMs <= 0 => 'Could not measure server response time',
                $ttfbPass => "Fast — server responded in {$ttfbMs}ms",
                default => "Slow — server responded in {$ttfbMs}ms; live AI retrieval may time out",
            },
            'meta' => "ttfb_ms={$ttfbMs}",
        ],
    ];

    $score = min(100, array_sum(array_column($rows, 'score')));

    return ['rows' => $rows, 'score' => $score, 'error' => null];
}

// ── Output ────────────────────────────────────────────────────────────────────

function write_csv(string $path, array $rows): void
{
    $fh = fopen($path, 'w');
    // Explicit escape: PHP 8.4 deprecates omitting it (default is being removed).
    fputcsv($fh, ['group', 'key', 'label', 'status', 'score', 'max_score', 'detail', 'meta'], escape: '\\');
    foreach ($rows as $r) {
        fputcsv($fh, [
            $r['group'], $r['key'], $r['label'], $r['pass'] ? 'pass' : 'improve',
            $r['score'], $r['max'], $r['detail'], $r['meta'],
        ], escape: '\\');
    }
    fclose($fh);
}

function write_html(string $path, string $url, int $score, array $rows): void
{
    $host = htmlspecialchars(parse_url($url, PHP_URL_HOST) ?: $url);
    $scoreColor = $score >= 75 ? 'var(--good)' : ($score >= 50 ? 'var(--warn)' : 'var(--bad)');
    $gradeWord = $score >= 90 ? 'Excellent' : ($score >= 75 ? 'Good' : ($score >= 50 ? 'Needs work' : 'At risk'));
    $tbody = '';
    foreach ($rows as $r) {
        $mark = $r['pass']
            ? '<span class="ok">✔ Pass</span>'
            : '<span class="warn">⚠ Improve</span>';
        $tbody .= '<tr><td class="signal">'.htmlspecialchars($r['label']).'</td>'
            .'<td class="result">'.$mark.'</td>'
            .'<td class="pts">'.$r['score'].' / '.$r['max'].'</td>'
            .'<td class="detail">'.htmlspecialchars($r['detail']).'</td></tr>';
    }
    $generated = gmdate('Y-m-d H:i').' UTC';
    $ver = VERSION;
    $html = <<<HTML
    <!DOCTYPE html>
    <html lang="en">
    <head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>AI-Readiness Report — {$host}</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@400;500;600;700&family=IBM+Plex+Sans:wght@400;500;600&family=IBM+Plex+Mono:wght@400;500&display=swap" rel="stylesheet">
    <style>
      /* ── Website Health Check report theme (teal) ── */
      :root {
        --ink: #0F1E33; --body: #33415C; --muted: #64748B; --soft: #94A3B8;
        --line: #E6EAF1; --line-strong: #C9D4E5; --bg: #ffffff; --bg-soft: #F5F7FA;
        --accent: #0D8A7E; --accent-tint: #E6F4F2; --accent-line: #BFE3DE;
        --good: #1F9D5B; --warn: #E3A11F; --bad: #D64541;
      }
      *, *::before, *::after { box-sizing: border-box; }
      body { font-family: 'IBM Plex Sans', system-ui, Helvetica, Arial, sans-serif;
             background: var(--bg-soft); color: var(--body); margin: 0; padding: 0 28px 40px;
             line-height: 1.55; }
      .wrap { max-width: 860px; margin: 0 auto; }
      .brandbar { display: flex; align-items: center; gap: 14px; padding: 18px 0 16px;
                  margin-bottom: 24px; border-bottom: 1px solid var(--line); flex-wrap: wrap; }
      .brandbar .logo { width: 30px; height: 30px; border-radius: 50%; flex: none;
        background: conic-gradient(var(--good) 0 76%, var(--line) 76% 100%);
        display: grid; place-items: center; }
      .brandbar .logo::before { content: ''; width: 20px; height: 20px; border-radius: 50%;
        background: var(--bg-soft); }
      .brandbar .brandname { font-family: 'Space Grotesk', sans-serif; font-weight: 700;
        font-size: 17px; color: var(--ink); }
      .brandbar .brandctx { color: var(--soft); font-size: 13px; }
      .brandbar .sp { flex: 1; }
      h1 { font-family: 'Space Grotesk', sans-serif; font-size: 1.6rem; margin: 6px 0 4px; color: var(--ink); }
      .lead { font-size: 0.9rem; color: var(--muted); margin: 0 0 16px; max-width: 620px; }
      .meta { font-size: 0.8rem; color: var(--muted); margin-bottom: 24px; }
      .meta strong { color: var(--ink); }
      .cards { display: flex; flex-wrap: wrap; gap: 12px; }
      .card { background: var(--bg); border: 1px solid var(--line); border-radius: 12px;
              padding: 16px 22px; min-width: 168px;
              box-shadow: 0 1px 2px rgba(15, 23, 42, .04); }
      .card-label { font-size: 0.72rem; color: var(--muted); text-transform: uppercase;
                    letter-spacing: .06em; }
      .card-score { font-family: 'Space Grotesk', sans-serif; font-size: 2.4rem; font-weight: 700;
                    line-height: 1.1; margin: 4px 0; }
      .card-score span { font-size: 1rem; color: var(--soft); font-weight: 400; }
      .card-sub { font-size: 0.72rem; color: var(--soft); text-transform: uppercase; letter-spacing: .05em; }
      .section-title { font-family: 'Space Grotesk', sans-serif; font-size: 0.8rem; font-weight: 700;
                       color: var(--muted); text-transform: uppercase; letter-spacing: .1em;
                       margin: 28px 0 10px; }
      .table-wrap { overflow-x: auto; border: 1px solid var(--line); border-radius: 12px;
                    background: var(--bg); }
      table { width: 100%; border-collapse: collapse; font-size: 0.82rem; color: var(--body); }
      th, td { padding: 10px 14px; text-align: left; border-bottom: 1px solid var(--line); }
      tr:last-child td { border-bottom: 0; }
      th { background: var(--bg-soft); color: var(--muted); font-weight: 600; font-size: 0.7rem;
           text-transform: uppercase; letter-spacing: .05em; white-space: nowrap; }
      td.signal { font-weight: 500; color: var(--ink); }
      td.result { text-align: center; white-space: nowrap; }
      td.pts { text-align: right; white-space: nowrap; font-variant-numeric: tabular-nums; color: var(--soft); }
      td.detail { color: var(--muted); }
      .ok { color: var(--good); font-weight: 600; }
      .warn { color: var(--warn); font-weight: 600; }
      tr:hover td { background: var(--accent-tint); }
      footer { color: var(--soft); font-size: 12px; margin-top: 22px; }
      @media print {
        body { background: #ffffff; padding: 0 12px; }
        .table-wrap { overflow: visible; }
        tr:hover td { background: none; }
      }
    </style>
    </head>
    <body><div class="wrap">
      <header class="brandbar">
        <span class="logo"></span>
        <span class="brandname">Website Health Check</span>
        <span class="sp"></span>
        <span class="brandctx">AI-Readiness report · powered by 2create</span>
      </header>
      <h1>AI-Readiness Report</h1>
      <p class="lead">How well generative search engines (ChatGPT, Perplexity, Google AI Overviews, Claude) can read this site.</p>
      <div class="meta">Site: <strong>{$host}</strong> &nbsp;|&nbsp; Generated: <strong>{$generated}</strong></div>
      <div class="cards">
        <div class="card">
          <div class="card-label">AI-Readiness score</div>
          <div class="card-score" style="color: {$scoreColor}">{$score}<span> / 100</span></div>
          <div class="card-sub">{$gradeWord}</div>
        </div>
      </div>
      <div class="section-title">Signals</div>
      <div class="table-wrap">
        <table>
          <tr><th>Signal</th><th style="text-align:center">Result</th><th style="text-align:right">Points</th><th>Detail</th></tr>
          {$tbody}
        </table>
      </div>
      <footer>Generated {$generated} · AI-Readiness Bulk Scanner v{$ver}</footer>
    </div></body></html>
    HTML;

    file_put_contents($path, $html);
}

// ── Main ──────────────────────────────────────────────────────────────────────
function main(): int
{
    $args = parse_args();
    fwrite(STDOUT, "AI-Readiness Bulk Scanner v".VERSION."\n");
    fwrite(STDOUT, "→ Checking {$args['url']}\n");

    $result = analyze($args);
    if ($result['error'] !== null) {
        fwrite(STDERR, "❌  {$result['error']}\n");

        return 1;
    }

    write_csv($args['csv'], $result['rows']);
    write_html($args['output'], $args['url'], $result['score'], $result['rows']);

    fwrite(STDOUT, "\nAI-Readiness score: {$result['score']}/100\n");
    foreach ($result['rows'] as $r) {
        $mark = $r['pass'] ? '✔' : '⚠';
        fwrite(STDOUT, sprintf("  %s  %-28s %2d/%-2d  %s\n", $mark, $r['label'], $r['score'], $r['max'], $r['detail']));
    }
    fwrite(STDOUT, "\n✅  HTML report → {$args['output']}\n");
    fwrite(STDOUT, "✅  CSV export  → {$args['csv']}\n");

    return 0;
}

exit(main());

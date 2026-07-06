# AI-Readiness Bulk Scanner

Check how well a website can be read by generative search engines — **ChatGPT search, Perplexity, Google AI Overviews, Claude** — and get a 0–100 AI-Readiness score in a self-contained HTML report + CSV export.

No API key, no account, no browser. Everything runs locally via plain PHP + cURL — the same lightweight, self-contained approach as the sibling [accessibility-bulk-scanner](https://github.com/simeon-zhelev/accessibility-bulk-scanner), [pagespeed-bulk-scanner](https://github.com/simeon-zhelev/pagespeed-bulk-scanner) and [broken-link-bulk-scanner](https://github.com/simeon-zhelev/broken-link-bulk-scanner).

## Why AI-readiness

AI assistants increasingly answer *before* anyone clicks through to your site — and they only cite pages they can actually fetch and parse. This scanner checks the concrete, technical signals that decide whether you show up:

| Signal | Points | What it checks |
|---|---:|---|
| **AI crawler access** | 30 | Does `robots.txt` allow GPTBot, OAI-SearchBot, ClaudeBot, PerplexityBot, Google-Extended, CCBot… ? Blocking one makes you invisible to that assistant. |
| **Structured data** | 25 | JSON-LD schema.org (12) + meta description (5) + Open Graph (4) + `<title>` (4). |
| **Server-rendered content** | 20 | Is the main text in the *raw* HTML, or does it need JavaScript? Most AI crawlers don't run JS. |
| **Semantic HTML** | 15 | Exactly one `<h1>` (6) + `<main>`/`<article>` (5) + real heading structure (4). |
| **Discoverability** | 10 | XML sitemap (5) + `llms.txt` (5). |

The points sum to 100. `robots.txt` and `llms.txt` are best-effort — absent means "not blocking" / "no llms.txt", never an error. Only an unreachable homepage fails the run.

## Quick start

```bash
php ai_readiness_scanner.php --url=https://example.com
```

Writes `ai_readiness_report.html` (open it in a browser) and `ai_readiness_report.csv`, and prints a summary:

```
AI-Readiness score: 84/100
  ✔  AI crawler access            30/30  All 9 major AI crawlers allowed
  ⚠  Meta description              0/5   Missing
  ✔  Server-rendered content      20/20  ~13790 chars of text in raw HTML
  …
```

Requirements: **PHP 8.1+** with the `curl` and `dom`/`mbstring` extensions. No Composer, no Node.

## Options

```
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
```

## CSV format

One row per signal, so the output is easy to parse or diff:

```
group,key,label,status,score,max_score,detail,meta
crawler_access,crawler_access,"AI crawler access",pass,30,30,"All 9 major AI crawlers allowed",allowed=9;total=9;blocked=
structured_data,json_ld,"Structured data (schema.org)",pass,12,12,"JSON-LD present",has_json_ld=1
rendered_content,server_rendered,"Server-rendered content",pass,20,20,"~13790 chars of text in raw HTML",server_rendered=1;chars=13790
…
```

- `status` is `pass` or `improve`; the AI-Readiness score is the sum of `score` (capped at 100).
- `meta` carries machine-readable values (`key=value`, lists pipe-joined) so downstream tools can reconstruct the full picture without scraping the HTML.

## Security

The fetcher follows redirects **manually** and re-checks the target host on every hop, refusing to follow a redirect to localhost or a private/reserved IP (cloud-metadata `169.254.169.254`, RFC1918, loopback, etc.). This built-in SSRF guard is on by default; pass `--allow-private` to disable it for trusted internal use. Still, run it against sites you're authorized to scan.

## License

MIT — see [LICENSE](LICENSE).

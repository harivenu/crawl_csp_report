# CSP Inventory & CDN Discovery Crawler (PHP)

A PHP-based crawler to **discover all external domains (CDNs, third-party services)** used across a website and generate **Content Security Policy (CSP)–ready reports**.

This tool is designed for large websites (1000+ pages) to help security and engineering teams build a **strict, auditable CSP** safely.

---

## 🎯 Purpose

Content Security Policy (CSP) requires a complete and accurate allowlist of external domains.  
Manually identifying these domains across a large site is unreliable and incomplete.

This tool helps you:

- Crawl all URLs from a sitemap
- Identify external domains used by pages
- Map resources to CSP directives
- Generate CSV & JSON reports for Excel-based CSP analysis
- Build a secure CSP before enforcing it

---

## 🚀 Features

- Crawls all URLs from a sitemap (supports sitemap index)
- Extracts external resources from HTML:
  - `script[src]` → `script-src`
  - `link[href]` → `style-src`, `manifest-src`
  - `img[src|srcset]` → `img-src`
  - `iframe[src]` → `frame-src`
  - `audio/video/source` → `media-src`
  - `object/embed` → `object-src`
- Detects `data:` and `blob:` usage
- Deduplicates domains
- Generates:
  - Domain summary report
  - Page-level findings
  - Full JSON audit report

---

## ❌ Limitations (Important)

This crawler **does NOT detect runtime network calls**, such as:

- `fetch()`
- `XMLHttpRequest`
- WebSockets
- JavaScript-triggered analytics beacons

These belong to `connect-src` and **must be discovered via CSP Report-Only in browsers**.

This tool should be used **together with CSP Report-Only** for full coverage.

---

## 📁 Output Files

### `csp_domain_summary.csv`
Best for CSP rule design.

| Column | Description |
|------|------------|
| CSP Directive | Suggested CSP directive |
| Source Type | domain / scheme |
| Source Value | Domain or scheme |
| Count | Pages where used |
| Sample Pages | Example URLs |

---

### `csp_page_findings.csv`
Best for debugging and validation.

| Column | Description |
|------|------------|
| Page URL | Crawled page |
| HTTP Code | Response status |
| Directive | CSP directive |
| Domains | External domains |

---

### `csp_report.json`
Complete structured audit data for automation and security reviews.

---

## 📦 Requirements

- PHP 8.0+
- PHP extensions:
  - curl
  - dom
  - libxml
  - openssl

Check installed extensions:

```bash
php -m

# Usage
php crawl_csp_report.php --sitemap="https://example.com/sitemap.xml"

php crawl_csp_report.php \
  --sitemap="https://example.com/sitemap.xml" \
  --out="./out" \
  --concurrency=10 \
  --timeout=20

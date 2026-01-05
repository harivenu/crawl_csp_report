<?php
/**
 * Crawl URLs from a sitemap and generate a CSP-related external domain report.
 *
 * Usage:
 *   php crawl_csp_report.php --sitemap="https://help.unicef.org/sitemap.xml" --out="./out" --concurrency=10 --limit=0
 *
 * Options:
 *   --sitemap      Required. Sitemap XML URL (or local file path).
 *   --out          Output directory (default: ./out)
 *   --concurrency  Number of parallel requests (default: 8)
 *   --limit        Limit number of URLs (0 = no limit) (default: 0)
 *   --timeout      Request timeout seconds (default: 20)
 *   --user-agent   User-Agent string (default: CSP-Inventory-Crawler/1.0)
 *
 * Notes:
 * - Requires PHP extensions: curl, dom, libxml, openssl
 * - This discovers external resource URLs from HTML (CDN inventory). It does NOT capture connect-src (XHR/fetch).
 */

ini_set('display_errors', '1');
error_reporting(E_ALL);

$options = getopt("", [
  "sitemap:",
  "out::",
  "concurrency::",
  "limit::",
  "timeout::",
  "user-agent::",
]);

$sitemap = $options["sitemap"] ?? null;
if (!$sitemap) {
  fwrite(STDERR, "Missing --sitemap\nExample: php crawl_csp_report.php --sitemap=\"https://help.unicef.org/sitemap.xml\"\n");
  exit(1);
}

$outDir = $options["out"] ?? "./out";
$concurrency = (int)($options["concurrency"] ?? 8);
$limit = (int)($options["limit"] ?? 0);
$timeout = (int)($options["timeout"] ?? 20);
$userAgent = $options["user-agent"] ?? "CSP-Inventory-Crawler/1.0";

if (!is_dir($outDir)) {
  if (!mkdir($outDir, 0775, true)) {
    fwrite(STDERR, "Failed to create output dir: $outDir\n");
    exit(1);
  }
}

function readSitemapUrls(string $sitemap): array {
  $xmlContent = null;

  // If it's a URL, fetch it; else read file.
  if (preg_match('#^https?://#i', $sitemap)) {
    $ch = curl_init($sitemap);
    curl_setopt_array($ch, [
      CURLOPT_RETURNTRANSFER => true,
      CURLOPT_FOLLOWLOCATION => true,
      CURLOPT_TIMEOUT => 30,
      CURLOPT_SSL_VERIFYPEER => true,
    ]);
    $xmlContent = curl_exec($ch);
    $code = curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
    if ($xmlContent === false || $code >= 400) {
      $err = curl_error($ch);
      curl_close($ch);
      throw new RuntimeException("Failed to fetch sitemap URL. HTTP=$code Error=$err");
    }
    curl_close($ch);
  } else {
    $xmlContent = @file_get_contents($sitemap);
    if ($xmlContent === false) {
      throw new RuntimeException("Failed to read sitemap file: $sitemap");
    }
  }

  libxml_use_internal_errors(true);
  $xml = simplexml_load_string($xmlContent);
  if (!$xml) {
    throw new RuntimeException("Invalid sitemap XML.");
  }

  $urls = [];

  // Supports both <urlset> and <sitemapindex> (nested sitemaps)
  if (isset($xml->url)) {
    foreach ($xml->url as $u) {
      $loc = (string)$u->loc;
      if ($loc) $urls[] = $loc;
    }
  } elseif (isset($xml->sitemap)) {
    foreach ($xml->sitemap as $sm) {
      $loc = (string)$sm->loc;
      if ($loc) {
        // Recursively read nested sitemap
        $urls = array_merge($urls, readSitemapUrls($loc));
      }
    }
  }

  // De-dupe, keep order
  $seen = [];
  $unique = [];
  foreach ($urls as $u) {
    if (!isset($seen[$u])) {
      $seen[$u] = true;
      $unique[] = $u;
    }
  }
  return $unique;
}

function normalizeUrl(string $baseUrl, string $maybeUrl): ?string {
  $maybeUrl = trim($maybeUrl);
  if ($maybeUrl === "" || str_starts_with($maybeUrl, "javascript:") || str_starts_with($maybeUrl, "mailto:") || str_starts_with($maybeUrl, "tel:")) {
    return null;
  }

  // srcset can contain multiple URLs - handled elsewhere.
  if (preg_match('#^https?://#i', $maybeUrl)) return $maybeUrl;

  // Protocol-relative: //cdn.example.com/x.js
  if (str_starts_with($maybeUrl, "//")) {
    $scheme = parse_url($baseUrl, PHP_URL_SCHEME) ?: "https";
    return $scheme . ":" . $maybeUrl;
  }

  // Data/blob
  if (preg_match('#^(data|blob):#i', $maybeUrl)) return $maybeUrl;

  // Relative path
  $base = parse_url($baseUrl);
  if (!$base || empty($base["host"])) return null;

  $scheme = $base["scheme"] ?? "https";
  $host = $base["host"];
  $port = isset($base["port"]) ? ":" . $base["port"] : "";
  $origin = $scheme . "://" . $host . $port;

  if (str_starts_with($maybeUrl, "/")) {
    return $origin . $maybeUrl;
  }

  // Relative to current directory
  $path = $base["path"] ?? "/";
  $dir = preg_replace('#/[^/]*$#', '/', $path);
  return $origin . $dir . $maybeUrl;
}

function getHostOrToken(string $url): string {
  if (preg_match('#^(data|blob):#i', $url, $m)) return strtolower($m[1]) . ":";
  $host = parse_url($url, PHP_URL_HOST);
  return $host ? strtolower($host) : "unknown";
}

function isSameSite(string $pageUrl, string $resourceUrl): bool {
  $pageHost = strtolower(parse_url($pageUrl, PHP_URL_HOST) ?? "");
  $resHost = strtolower(parse_url($resourceUrl, PHP_URL_HOST) ?? "");
  if ($pageHost === "" || $resHost === "") return false;
  return $pageHost === $resHost;
}

function guessDirective(string $resourceCategory, string $url): string {
  // Very practical mapping for CSP inventory.
  $hostToken = getHostOrToken($url);
  if ($hostToken === "data:" || $hostToken === "blob:") {
    // These show up most commonly in img/style contexts; keep category-based
  }
  return match ($resourceCategory) {
    "script" => "script-src",
    "style" => "style-src",
    "img" => "img-src",
    "frame" => "frame-src",
    "font" => "font-src",
    "media" => "media-src",
    "manifest" => "manifest-src",
    "object" => "object-src",
    "worker" => "worker-src",
    default => "default-src",
  };
}

function parseHtmlForResources(string $pageUrl, string $html): array {
  $results = []; // each: [category, url]

  libxml_use_internal_errors(true);
  $dom = new DOMDocument();
  // Some pages have malformed HTML; suppress warnings
  @$dom->loadHTML($html);

  $xpath = new DOMXPath($dom);

  // Scripts
  foreach ($xpath->query("//script[@src]") as $node) {
    $u = normalizeUrl($pageUrl, $node->getAttribute("src"));
    if ($u) $results[] = ["script", $u];
  }

  // Stylesheets and other link types
  foreach ($xpath->query("//link[@href]") as $node) {
    $rel = strtolower(trim($node->getAttribute("rel")));
    $href = $node->getAttribute("href");
    $u = normalizeUrl($pageUrl, $href);
    if (!$u) continue;

    if (str_contains($rel, "stylesheet")) $results[] = ["style", $u];
    elseif (str_contains($rel, "manifest")) $results[] = ["manifest", $u];
    else {
      // preconnect/dns-prefetch/icon/etc. still helpful inventory; treat as default-src-ish
      $results[] = ["link-other", $u];
    }
  }

  // Images
  foreach ($xpath->query("//img[@src]") as $node) {
    $u = normalizeUrl($pageUrl, $node->getAttribute("src"));
    if ($u) $results[] = ["img", $u];
  }
  // srcset parsing
  foreach ($xpath->query("//img[@srcset]") as $node) {
    $srcset = $node->getAttribute("srcset");
    $parts = preg_split('/\s*,\s*/', $srcset);
    foreach ($parts as $p) {
      $urlPart = trim(preg_split('/\s+/', trim($p))[0] ?? "");
      $u = normalizeUrl($pageUrl, $urlPart);
      if ($u) $results[] = ["img", $u];
    }
  }

  // Iframes
  foreach ($xpath->query("//iframe[@src]") as $node) {
    $u = normalizeUrl($pageUrl, $node->getAttribute("src"));
    if ($u) $results[] = ["frame", $u];
  }

  // Media
  foreach ($xpath->query("//audio[@src] | //video[@src] | //source[@src]") as $node) {
    $u = normalizeUrl($pageUrl, $node->getAttribute("src"));
    if ($u) $results[] = ["media", $u];
  }

  // Object/embed
  foreach ($xpath->query("//object[@data]") as $node) {
    $u = normalizeUrl($pageUrl, $node->getAttribute("data"));
    if ($u) $results[] = ["object", $u];
  }
  foreach ($xpath->query("//embed[@src]") as $node) {
    $u = normalizeUrl($pageUrl, $node->getAttribute("src"));
    if ($u) $results[] = ["object", $u];
  }

  // Fonts (rarely directly referenced in HTML, but sometimes via <link rel=preload as=font>)
  foreach ($xpath->query("//link[@href]") as $node) {
    $as = strtolower(trim($node->getAttribute("as")));
    if ($as === "font") {
      $u = normalizeUrl($pageUrl, $node->getAttribute("href"));
      if ($u) $results[] = ["font", $u];
    }
  }

  return $results;
}

function fetchUrlsMulti(array $urls, int $concurrency, int $timeout, string $userAgent): array {
  $mh = curl_multi_init();
  $handles = [];
  $results = []; // url => [code, body, error]

  $queue = $urls;
  $active = null;

  $addHandle = function(string $url) use (&$mh, &$handles, $timeout, $userAgent) {
    $ch = curl_init($url);
    curl_setopt_array($ch, [
      CURLOPT_RETURNTRANSFER => true,
      CURLOPT_FOLLOWLOCATION => true,
      CURLOPT_TIMEOUT => $timeout,
      CURLOPT_CONNECTTIMEOUT => min(10, $timeout),
      CURLOPT_USERAGENT => $userAgent,
      CURLOPT_SSL_VERIFYPEER => true,
      CURLOPT_SSL_VERIFYHOST => 2,
      CURLOPT_HTTPHEADER => [
        "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
      ],
    ]);
    curl_multi_add_handle($mh, $ch);
    $handles[(int)$ch] = ["handle" => $ch, "url" => $url];
  };

  // Prime the pool
  for ($i = 0; $i < $concurrency && !empty($queue); $i++) {
    $addHandle(array_shift($queue));
  }

  do {
    do {
      $status = curl_multi_exec($mh, $active);
    } while ($status === CURLM_CALL_MULTI_PERFORM);

    // Read completed
    while ($info = curl_multi_info_read($mh)) {
      $ch = $info["handle"];
      $key = (int)$ch;
      $url = $handles[$key]["url"] ?? "unknown";

      $body = curl_multi_getcontent($ch);
      $code = curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
      $err  = curl_error($ch);

      $results[$url] = [
        "code" => $code,
        "body" => $body,
        "error" => $err,
      ];

      curl_multi_remove_handle($mh, $ch);
      curl_close($ch);
      unset($handles[$key]);

      // Add next from queue
      if (!empty($queue)) {
        $addHandle(array_shift($queue));
      }
    }

    if ($active) {
      curl_multi_select($mh, 1.0);
    }
  } while ($active || !empty($handles));

  curl_multi_close($mh);
  return $results;
}

// ------------------------- Main -------------------------
try {
  $urls = readSitemapUrls($sitemap);
} catch (Throwable $e) {
  fwrite(STDERR, "Error reading sitemap: " . $e->getMessage() . "\n");
  exit(1);
}

if ($limit > 0) {
  $urls = array_slice($urls, 0, $limit);
}

echo "URLs loaded: " . count($urls) . "\n";
echo "Crawling with concurrency={$concurrency} timeout={$timeout}s\n";

$responses = fetchUrlsMulti($urls, $concurrency, $timeout, $userAgent);

// Aggregation structures
$pageFindings = [];   // pageUrl => [directive => [domains...]]
$domainSummary = [];  // directive => domain => ["count" => int, "pages" => [samples]]

foreach ($responses as $pageUrl => $resp) {
  $code = $resp["code"];
  $err = $resp["error"];
  $body = $resp["body"];

  if ($code < 200 || $code >= 400 || !$body) {
    $pageFindings[$pageUrl] = [
      "_fetch" => [
        "status" => "error",
        "http_code" => $code,
        "error" => $err,
      ]
    ];
    continue;
  }

  $resources = parseHtmlForResources($pageUrl, $body);

  $perPage = [
    "_fetch" => [
      "status" => "ok",
      "http_code" => $code,
    ]
  ];

  foreach ($resources as [$category, $resourceUrl]) {
    // Only inventory external domains (CDNs / third-party). Keep data:/blob: too.
    $directive = guessDirective($category === "link-other" ? "default" : $category, $resourceUrl);

    $token = getHostOrToken($resourceUrl);
    $isExternal = true;

    // Treat same-site hosts as "self" (skip), except data/blob.
    if ($token !== "data:" && $token !== "blob:" && isSameSite($pageUrl, $resourceUrl)) {
      $isExternal = false;
    }

    if (!$isExternal) continue;

    if (!isset($perPage[$directive])) $perPage[$directive] = [];
    if (!in_array($token, $perPage[$directive], true)) $perPage[$directive][] = $token;

    if (!isset($domainSummary[$directive])) $domainSummary[$directive] = [];
    if (!isset($domainSummary[$directive][$token])) {
      $domainSummary[$directive][$token] = ["count" => 0, "pages" => []];
    }
    $domainSummary[$directive][$token]["count"] += 1;

    // store up to 5 sample pages per domain
    if (count($domainSummary[$directive][$token]["pages"]) < 5 && !in_array($pageUrl, $domainSummary[$directive][$token]["pages"], true)) {
      $domainSummary[$directive][$token]["pages"][] = $pageUrl;
    }
  }

  $pageFindings[$pageUrl] = $perPage;
}

// Write JSON report
$report = [
  "generated_at" => date('c'),
  "sitemap" => $sitemap,
  "total_urls" => count($urls),
  "domain_summary" => $domainSummary,
  "page_findings" => $pageFindings,
];

file_put_contents($outDir . "/csp_report.json", json_encode($report, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));

// Write CSV: domain summary
$csv1 = fopen($outDir . "/csp_domain_summary.csv", "w");
fputcsv($csv1, ["CSP Directive", "Source Type", "Source Value", "Count", "Sample Pages"]);
foreach ($domainSummary as $directive => $domains) {
  // sort by count desc
  uasort($domains, fn($a, $b) => $b["count"] <=> $a["count"]);
  foreach ($domains as $domain => $meta) {
    $sourceType = ($domain === "data:" || $domain === "blob:") ? "scheme" : "domain";
    $samplePages = implode(" | ", $meta["pages"]);
    fputcsv($csv1, [$directive, $sourceType, $domain, $meta["count"], $samplePages]);
  }
}
fclose($csv1);

// Write CSV: per page findings
$csv2 = fopen($outDir . "/csp_page_findings.csv", "w");
fputcsv($csv2, ["Page URL", "HTTP Code", "Directive", "Domains (deduped)"]);
foreach ($pageFindings as $pageUrl => $data) {
  $httpCode = $data["_fetch"]["http_code"] ?? "";
  $directives = array_filter(array_keys($data), fn($k) => $k !== "_fetch");
  if (empty($directives)) {
    fputcsv($csv2, [$pageUrl, $httpCode, "", ""]);
    continue;
  }
  foreach ($directives as $d) {
    $domains = is_array($data[$d]) ? implode(", ", $data[$d]) : "";
    fputcsv($csv2, [$pageUrl, $httpCode, $d, $domains]);
  }
}
fclose($csv2);

echo "Done.\n";
echo "Outputs:\n";
echo " - {$outDir}/csp_report.json\n";
echo " - {$outDir}/csp_domain_summary.csv\n";
echo " - {$outDir}/csp_page_findings.csv\n";

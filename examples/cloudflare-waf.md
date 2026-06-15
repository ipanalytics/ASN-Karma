# Cloudflare WAF

Use ASN Karma as enrichment before enforcement. Start with the `high` and `critical` ASN tier files in log or challenge mode, then promote rules only after local false-positive review.

```sh
curl -fsSL \
  https://github.com/ipanalytics/ASN-Karma/releases/latest/download/high-risk-asn-high.txt \
  -o high-risk-asn-high.txt
```

Cloudflare custom rules can match ASN values directly. Convert `AS13335` style lines to numeric ASN values and exclude comment lines:

```sh
awk '!/^#/ { sub(/^AS/, "", $1); print $1 }' high-risk-asn-high.txt
```

Recommended action mapping:

| ASN Karma tier | Cloudflare action |
| --- | --- |
| `critical` | managed challenge or block after review |
| `high` | managed challenge |
| `watch` | log/enrich only |

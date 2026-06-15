# OPNsense Alias

Use derived prefix artifacts for firewall aliases. These files are generated from ASN expansion and are not source evidence.

```text
https://github.com/ipanalytics/ASN-Karma/releases/latest/download/high-risk-asn-prefixes-critical.txt
https://github.com/ipanalytics/ASN-Karma/releases/latest/download/high-risk-asn-prefixes-high.txt
```

Recommended deployment:

| Prefix tier | Suggested use |
| --- | --- |
| `critical` | block or strict policy after local validation |
| `high` | rate-limit, challenge, or monitor |
| `watch` | logging and correlation |

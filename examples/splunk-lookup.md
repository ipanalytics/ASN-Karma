# Splunk Lookup

Download `asn-summary.csv` as a lookup table:

```sh
curl -fsSL \
  https://github.com/ipanalytics/ASN-Karma/releases/latest/download/asn-summary.csv \
  -o asn_summary.csv
```

Example SPL:

```spl
index=proxy
| lookup asn_summary.csv asn OUTPUT risk_score risk_level observed_records source_count recommended_action
| stats count by asn risk_level recommended_action
```

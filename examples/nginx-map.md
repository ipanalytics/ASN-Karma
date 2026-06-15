# NGINX Map

ASN Karma does not perform ASN lookup at request time. For NGINX, use the dataset upstream in a log enrichment or edge policy pipeline, then write a generated map file from local telemetry.

Example generated map:

```nginx
map $remote_asn $asn_karma_tier {
    default "";
    64500 "high";
    64501 "watch";
}
```

Use the map in access logs or rate-limit keys:

```nginx
log_format main '$remote_addr asn=$remote_asn asn_karma=$asn_karma_tier "$request" $status';
```

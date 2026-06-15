package prefixes

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"time"

	"asn-karma/internal/model"
)

type RIPEConfig struct {
	Endpoint string
	Timeout  time.Duration
	Limit    int
}

type ripeResponse struct {
	Data struct {
		Prefixes []struct {
			Prefix string `json:"prefix"`
		} `json:"prefixes"`
	} `json:"data"`
}

func ExpandForRiskRecords(ctx context.Context, records []model.RiskRecord, cfg RIPEConfig) (map[int][]string, error) {
	if cfg.Endpoint == "" {
		cfg.Endpoint = "https://stat.ripe.net/data/announced-prefixes/data.json"
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 20 * time.Second
	}

	client := &http.Client{Timeout: cfg.Timeout}
	out := map[int][]string{}
	var firstErr error
	attempted := 0
	for _, rec := range records {
		if rec.RiskLevel != "critical" && rec.RiskLevel != "high" && rec.RiskLevel != "watch" {
			continue
		}
		if cfg.Limit > 0 && attempted >= cfg.Limit {
			break
		}
		attempted++
		prefixes, err := fetch(ctx, client, cfg.Endpoint, rec.ASN)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		out[rec.ASN] = prefixes
	}
	return out, firstErr
}

func ApplyCounts(records []model.RiskRecord, expanded map[int][]string) {
	for i := range records {
		records[i].ExpandedPrefixCount = len(expanded[records[i].ASN])
		records[i].ExpandedPrefixesAreEvidence = false
	}
}

func fetch(ctx context.Context, client *http.Client, endpoint string, asn int) ([]string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("%s?resource=AS%d", endpoint, asn), nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch RIPEstat AS%d prefixes: %w", asn, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, fmt.Errorf("fetch RIPEstat AS%d prefixes: status %d", asn, resp.StatusCode)
	}

	var parsed ripeResponse
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return nil, err
	}
	prefixes := make([]string, 0, len(parsed.Data.Prefixes))
	seen := map[string]bool{}
	for _, item := range parsed.Data.Prefixes {
		if item.Prefix == "" || seen[item.Prefix] {
			continue
		}
		seen[item.Prefix] = true
		prefixes = append(prefixes, item.Prefix)
	}
	sort.Strings(prefixes)
	return prefixes, nil
}

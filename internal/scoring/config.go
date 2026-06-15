package scoring

import (
	"encoding/json"
	"os"
)

type Config struct {
	EvidenceWindowDays int            `json:"evidence_window_days"`
	ThreatWeights      map[string]int `json:"threat_weights"`
	LargeCloudASNs     []int          `json:"large_cloud_asns"`
	ReviewASNs         []int          `json:"review_asns"`
	ReviewNameKeywords []string       `json:"review_name_keywords"`
	AllowlistASNs      []int          `json:"allowlist_asns"`
	WatchlistASNs      []int          `json:"watchlist_asns"`
}

func LoadConfig(path string) (Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return Config{}, err
	}
	var cfg Config
	if err := json.Unmarshal(b, &cfg); err != nil {
		return Config{}, err
	}
	if cfg.EvidenceWindowDays == 0 {
		cfg.EvidenceWindowDays = 30
	}
	return cfg, nil
}

package model

import (
	"sort"
	"time"
)

type ObservedRecord struct {
	ASN          int
	ASNName      string
	Country      string
	IP           string
	CIDR         string
	Source       string
	ThreatLabels []string
}

type ASNAggregate struct {
	ASN          int
	ASNName      string
	Country      string
	Records      int
	UniqueCIDRs  map[string]bool
	Sources      map[string]bool
	Countries    map[string]int
	ThreatCounts map[string]int
}

type RiskRecord struct {
	ASN                         int            `json:"asn"`
	ASNName                     string         `json:"asn_name,omitempty"`
	Country                     string         `json:"country,omitempty"`
	RiskScore                   int            `json:"risk_score"`
	RiskLevel                   string         `json:"risk_level"`
	RecommendedAction           string         `json:"recommended_action"`
	ObservedRecords             int            `json:"observed_records"`
	UniqueObservedCIDRs         int            `json:"unique_observed_cidrs"`
	SourceCount                 int            `json:"source_count"`
	SourceDiversity             int            `json:"source_diversity"`
	TopThreatLabels             map[string]int `json:"top_threat_labels"`
	EvidenceWindowDays          int            `json:"evidence_window_days"`
	PersistenceDays30D          int            `json:"persistence_days_30d"`
	ExpandedPrefixCount         int            `json:"expanded_prefix_count"`
	ExpandedPrefixesAreEvidence bool           `json:"expanded_prefixes_are_evidence"`
	LargeCloud                  bool           `json:"large_cloud"`
	Watchlist                   bool           `json:"watchlist"`
	BuiltAt                     time.Time      `json:"built_at"`
}

func AggregateRecords(records []ObservedRecord) []ASNAggregate {
	byASN := map[int]*ASNAggregate{}
	for _, rec := range records {
		agg := byASN[rec.ASN]
		if agg == nil {
			agg = &ASNAggregate{
				ASN:          rec.ASN,
				UniqueCIDRs:  map[string]bool{},
				Sources:      map[string]bool{},
				Countries:    map[string]int{},
				ThreatCounts: map[string]int{},
			}
			byASN[rec.ASN] = agg
		}

		if agg.ASNName == "" {
			agg.ASNName = rec.ASNName
		}
		if rec.Country != "" {
			agg.Countries[rec.Country]++
			if agg.Country == "" || agg.Countries[rec.Country] > agg.Countries[agg.Country] {
				agg.Country = rec.Country
			}
		}
		agg.Records++
		if rec.CIDR != "" {
			agg.UniqueCIDRs[rec.CIDR] = true
		}
		if rec.Source != "" {
			agg.Sources[rec.Source] = true
		}
		for _, label := range rec.ThreatLabels {
			agg.ThreatCounts[label]++
		}
	}

	out := make([]ASNAggregate, 0, len(byASN))
	for _, agg := range byASN {
		out = append(out, *agg)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].ASN < out[j].ASN
	})
	return out
}

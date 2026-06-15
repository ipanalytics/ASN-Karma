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
	ConfidenceScore             int            `json:"confidence_score"`
	Confidence                  string         `json:"confidence"`
	RecommendedAction           string         `json:"recommended_action"`
	ObservedRecords             int            `json:"observed_records"`
	UniqueObservedCIDRs         int            `json:"unique_observed_cidrs"`
	SourceCount                 int            `json:"source_count"`
	SourceDiversity             int            `json:"source_diversity"`
	TopThreatLabels             map[string]int `json:"top_threat_labels"`
	EvidenceWindowDays          int            `json:"evidence_window_days"`
	PersistenceDays30D          int            `json:"persistence_days_30d"`
	ActiveDays7D                int            `json:"active_days_7d"`
	ActiveDays30D               int            `json:"active_days_30d"`
	ActiveDays90D               int            `json:"active_days_90d"`
	FirstSeen                   string         `json:"first_seen,omitempty"`
	LastSeen                    string         `json:"last_seen,omitempty"`
	Trend                       string         `json:"trend"`
	EvidenceDelta1D             int            `json:"evidence_delta_1d"`
	ExpandedPrefixCount         int            `json:"expanded_prefix_count"`
	ExpandedPrefixesAreEvidence bool           `json:"expanded_prefixes_are_evidence"`
	LargeCloud                  bool           `json:"large_cloud"`
	Watchlist                   bool           `json:"watchlist"`
	BuiltAt                     time.Time      `json:"built_at"`
}

type HistorySignal struct {
	FirstSeen       string
	LastSeen        string
	ActiveDays7D    int
	ActiveDays30D   int
	ActiveDays90D   int
	PreviousRecords int
	Trend           string
	EvidenceDelta1D int
}

type BuildStats struct {
	BuiltAt             time.Time      `json:"built_at"`
	DurationSeconds     float64        `json:"duration_seconds"`
	InputRecords        int            `json:"input_records"`
	RecordsWithASN      int            `json:"records_with_asn"`
	RecordsNeedingASN   int            `json:"records_needing_asn"`
	RecordsEnriched     int            `json:"records_enriched"`
	RecordsUnmapped     int            `json:"records_unmapped"`
	UniqueEnrichQueries int            `json:"unique_enrich_queries"`
	MappedEnrichQueries int            `json:"mapped_enrich_queries"`
	UniqueASNs          int            `json:"unique_asns"`
	UniqueSources       int            `json:"unique_sources"`
	ExpandedASNs        int            `json:"expanded_asns"`
	ExpandedPrefixes    int            `json:"expanded_prefixes"`
	CriticalCount       int            `json:"critical_count"`
	HighCount           int            `json:"high_count"`
	WatchCount          int            `json:"watch_count"`
	LowCount            int            `json:"low_count"`
	TopUnmappedSamples  []string       `json:"top_unmapped_samples,omitempty"`
	TopSources          map[string]int `json:"top_sources,omitempty"`
}

func AggregateRecords(records []ObservedRecord) []ASNAggregate {
	byASN := map[int]*ASNAggregate{}
	for _, rec := range records {
		if rec.ASN == 0 {
			continue
		}
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

package scoring

import (
	"context"
	"math"
	"sort"
	"time"

	"asn-karma/internal/model"
)

func ScoreAll(_ context.Context, cfg Config, aggregates []model.ASNAggregate, historySignals map[int]model.HistorySignal, builtAt time.Time) []model.RiskRecord {
	largeCloud := intSet(cfg.LargeCloudASNs)
	allowlist := intSet(cfg.AllowlistASNs)
	watchlist := intSet(cfg.WatchlistASNs)

	out := make([]model.RiskRecord, 0, len(aggregates))
	for _, agg := range aggregates {
		history := historySignals[agg.ASN]
		score := scoreASN(cfg, agg, history)
		if largeCloud[agg.ASN] {
			score -= 20
		}
		if allowlist[agg.ASN] {
			score -= 60
		}
		score = clamp(score, 0, 100)

		level, action := levelAndAction(score, len(agg.Sources), agg.ThreatCounts, largeCloud[agg.ASN])
		if watchlist[agg.ASN] && score < 50 {
			level = "watch"
			action = "enrichment_or_log_only"
		}
		confidenceScore, confidence := confidenceFor(agg, history)
		trend := trendFor(agg.Records, history.PreviousRecords)
		firstSeen := history.FirstSeen
		if firstSeen == "" {
			firstSeen = builtAt.UTC().Format(time.DateOnly)
		}
		active7 := clamp(history.ActiveDays7D+1, 1, 7)
		active30 := clamp(history.ActiveDays30D+1, 1, 30)
		active90 := clamp(history.ActiveDays90D+1, 1, 90)

		out = append(out, model.RiskRecord{
			ASN:                         agg.ASN,
			ASNName:                     agg.ASNName,
			Country:                     agg.Country,
			RiskScore:                   score,
			RiskLevel:                   level,
			ConfidenceScore:             confidenceScore,
			Confidence:                  confidence,
			RecommendedAction:           action,
			ObservedRecords:             agg.Records,
			UniqueObservedCIDRs:         len(agg.UniqueCIDRs),
			SourceCount:                 len(agg.Sources),
			SourceDiversity:             len(agg.Sources),
			TopThreatLabels:             topThreats(agg.ThreatCounts, 8),
			EvidenceWindowDays:          cfg.EvidenceWindowDays,
			PersistenceDays30D:          active30,
			ActiveDays7D:                active7,
			ActiveDays30D:               active30,
			ActiveDays90D:               active90,
			FirstSeen:                   firstSeen,
			LastSeen:                    builtAt.UTC().Format(time.DateOnly),
			Trend:                       trend,
			EvidenceDelta1D:             agg.Records - history.PreviousRecords,
			ExpandedPrefixCount:         0,
			ExpandedPrefixesAreEvidence: false,
			LargeCloud:                  largeCloud[agg.ASN],
			Watchlist:                   watchlist[agg.ASN],
			BuiltAt:                     builtAt,
		})
	}

	sort.Slice(out, func(i, j int) bool {
		if out[i].RiskScore == out[j].RiskScore {
			return out[i].ASN < out[j].ASN
		}
		return out[i].RiskScore > out[j].RiskScore
	})
	return out
}

func scoreASN(cfg Config, agg model.ASNAggregate, history model.HistorySignal) int {
	sourceDiversity := clamp(len(agg.Sources)*12, 0, 25)
	threatSeverity := 0
	for label, count := range agg.ThreatCounts {
		weight := cfg.ThreatWeights[label]
		if weight == 0 {
			weight = 20
		}
		threatSeverity = max(threatSeverity, int(math.Round(float64(weight)*math.Min(1, float64(count)/10))))
	}
	threatSeverity = clamp(threatSeverity/4, 0, 25)
	recentActivity := clamp(int(math.Log10(float64(agg.Records)+1)*12), 0, 20)
	persistence := clamp(history.ActiveDays30D/2, 0, 15)
	abuseDensityProxy := clamp(int(math.Log10(float64(len(agg.UniqueCIDRs)+1))*8), 0, 10)
	cybercrimeBonus := 0
	if agg.ThreatCounts["prefix_cybercrime"] > 0 || agg.ThreatCounts["c2_ioc"] > 0 {
		cybercrimeBonus = 5
	}

	return sourceDiversity + threatSeverity + recentActivity + persistence + abuseDensityProxy + cybercrimeBonus
}

func confidenceFor(agg model.ASNAggregate, history model.HistorySignal) (int, string) {
	score := 0
	score += clamp(len(agg.Sources)*15, 0, 45)
	score += clamp(history.ActiveDays30D*2, 0, 30)
	score += clamp(int(math.Log10(float64(agg.Records)+1)*12), 0, 20)
	if len(agg.ThreatCounts) > 1 {
		score += 5
	}
	score = clamp(score, 0, 100)
	switch {
	case score >= 75:
		return score, "high"
	case score >= 45:
		return score, "medium"
	default:
		return score, "low"
	}
}

func trendFor(current int, previous int) string {
	if previous == 0 {
		return "new"
	}
	delta := current - previous
	switch {
	case delta > previous/4:
		return "up"
	case delta < -previous/4:
		return "down"
	default:
		return "flat"
	}
}

func levelAndAction(score, sourceDiversity int, threats map[string]int, largeCloud bool) (string, string) {
	hasHeavyThreat := threats["c2_ioc"] > 0 || threats["malware_host_active"] > 0 || threats["prefix_cybercrime"] > 0
	if score >= 90 && sourceDiversity >= 3 && hasHeavyThreat && !largeCloud {
		return "critical", "block_drop_or_challenge"
	}
	if score >= 75 && sourceDiversity >= 2 {
		return "high", "challenge_or_rate_limit"
	}
	if score >= 50 {
		return "watch", "enrichment_or_log_only"
	}
	return "low", "no_action"
}

func topThreats(in map[string]int, limit int) map[string]int {
	type pair struct {
		key string
		val int
	}
	pairs := make([]pair, 0, len(in))
	for k, v := range in {
		pairs = append(pairs, pair{k, v})
	}
	sort.Slice(pairs, func(i, j int) bool {
		if pairs[i].val == pairs[j].val {
			return pairs[i].key < pairs[j].key
		}
		return pairs[i].val > pairs[j].val
	})

	out := map[string]int{}
	for i, pair := range pairs {
		if i >= limit {
			break
		}
		out[pair.key] = pair.val
	}
	return out
}

func intSet(values []int) map[int]bool {
	out := map[int]bool{}
	for _, v := range values {
		out[v] = true
	}
	return out
}

func clamp(n, lo, hi int) int {
	if n < lo {
		return lo
	}
	if n > hi {
		return hi
	}
	return n
}

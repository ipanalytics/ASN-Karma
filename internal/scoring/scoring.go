package scoring

import (
	"context"
	"math"
	"sort"
	"time"

	"asn-karma/internal/model"
)

func ScoreAll(_ context.Context, cfg Config, aggregates []model.ASNAggregate, builtAt time.Time) []model.RiskRecord {
	largeCloud := intSet(cfg.LargeCloudASNs)
	allowlist := intSet(cfg.AllowlistASNs)
	watchlist := intSet(cfg.WatchlistASNs)

	out := make([]model.RiskRecord, 0, len(aggregates))
	for _, agg := range aggregates {
		score := scoreASN(cfg, agg)
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

		out = append(out, model.RiskRecord{
			ASN:                         agg.ASN,
			ASNName:                     agg.ASNName,
			Country:                     agg.Country,
			RiskScore:                   score,
			RiskLevel:                   level,
			RecommendedAction:           action,
			ObservedRecords:             agg.Records,
			UniqueObservedCIDRs:         len(agg.UniqueCIDRs),
			SourceCount:                 len(agg.Sources),
			SourceDiversity:             len(agg.Sources),
			TopThreatLabels:             topThreats(agg.ThreatCounts, 8),
			EvidenceWindowDays:          cfg.EvidenceWindowDays,
			PersistenceDays30D:          0,
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

func scoreASN(cfg Config, agg model.ASNAggregate) int {
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
	persistence := 0
	abuseDensityProxy := clamp(int(math.Log10(float64(len(agg.UniqueCIDRs)+1))*8), 0, 10)
	cybercrimeBonus := 0
	if agg.ThreatCounts["prefix_cybercrime"] > 0 || agg.ThreatCounts["c2_ioc"] > 0 {
		cybercrimeBonus = 5
	}

	return sourceDiversity + threatSeverity + recentActivity + persistence + abuseDensityProxy + cybercrimeBonus
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

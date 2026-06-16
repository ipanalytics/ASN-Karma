package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"sort"
	"time"

	"asn-karma/internal/blackroute"
	"asn-karma/internal/enrich"
	"asn-karma/internal/history"
	"asn-karma/internal/model"
	"asn-karma/internal/output"
	"asn-karma/internal/prefixes"
	"asn-karma/internal/scoring"
)

func main() {
	var (
		inputPath    = flag.String("input", "data/blackroute.jsonl", "path to BlackRoute JSONL")
		outputDir    = flag.String("out", "release", "directory for release artifacts")
		configPath   = flag.String("config", "configs/scoring.json", "path to scoring config")
		historyPath  = flag.String("history", "data/history/asn_daily.jsonl", "path to persisted ASN daily history")
		readmePath   = flag.String("readme", "", "optional README path to update with the latest ASN evidence table")
		releaseURL   = flag.String("release-url", "https://github.com/ipanalytics/ASN-Karma/releases/latest/download", "base URL for README release artifact links")
		asnEnrich    = flag.Bool("asn-enrich", true, "enrich records without ASN using Team Cymru bulk whois")
		cymruAddr    = flag.String("cymru-addr", "whois.cymru.com:43", "Team Cymru whois address")
		cymruBatch   = flag.Int("cymru-batch", 10000, "Team Cymru enrichment batch size")
		cymruLimit   = flag.Int("cymru-limit", 0, "maximum unique IP/CIDR representatives to enrich; 0 means no limit")
		prefixExpand = flag.Bool("prefix-expand", true, "expand high-risk ASN tiers to announced prefixes using RIPEstat")
		prefixLimit  = flag.Int("prefix-limit", 500, "maximum ASN records to expand to prefixes; 0 means no limit")
		prefixStrict = flag.Bool("prefix-strict", false, "fail the build if RIPEstat prefix expansion fails")
		allowEmpty   = flag.Bool("allow-empty", false, "allow a build that produces zero ASN risk records")
		builtAt      = flag.String("built-at", "", "override build timestamp in RFC3339 format")
	)
	flag.Parse()
	startedAt := time.Now()

	cfg, err := scoring.LoadConfig(*configPath)
	if err != nil {
		log.Fatalf("load config: %v", err)
	}

	ts := time.Now().UTC()
	if *builtAt != "" {
		ts, err = time.Parse(time.RFC3339, *builtAt)
		if err != nil {
			log.Fatalf("parse -built-at: %v", err)
		}
	}

	records, err := blackroute.ReadJSONL(*inputPath)
	if err != nil {
		log.Fatalf("read blackroute jsonl: %v", err)
	}
	stats := initialStats(records, ts)

	if *asnEnrich {
		enrichStats, err := enrich.EnrichWithTeamCymru(context.Background(), records, enrich.CymruConfig{
			Address:   *cymruAddr,
			BatchSize: *cymruBatch,
			Limit:     *cymruLimit,
		})
		if err != nil {
			log.Fatalf("enrich ASN with Team Cymru: %v", err)
		}
		fmt.Fprintf(
			os.Stderr,
			"asn enrichment: records_needing_asn=%d unique_queries=%d mapped_queries=%d enriched_records=%d\n",
			enrichStats.RecordsNeedingASN,
			enrichStats.UniqueQueries,
			enrichStats.MappedQueries,
			enrichStats.EnrichedRecords,
		)
		stats.RecordsNeedingASN = enrichStats.RecordsNeedingASN
		stats.UniqueEnrichQueries = enrichStats.UniqueQueries
		stats.MappedEnrichQueries = enrichStats.MappedQueries
		stats.RecordsEnriched = enrichStats.EnrichedRecords
	}
	stats.RecordsUnmapped = countRecordsWithoutASN(records)
	stats.TopUnmappedSamples = topUnmappedSamples(records, 10)

	aggregates := model.AggregateRecords(records)
	historySignals, err := history.LoadSignals(*historyPath, ts)
	if err != nil {
		log.Fatalf("load history: %v", err)
	}
	previousSnapshots, err := history.LoadLatestSnapshots(*historyPath, ts)
	if err != nil {
		log.Fatalf("load latest history snapshots: %v", err)
	}
	results := scoring.ScoreAll(context.Background(), cfg, aggregates, historySignals, ts)
	if len(results) == 0 && !*allowEmpty {
		log.Fatalf("no ASN risk records produced after enrichment")
	}
	expandedPrefixes := map[int][]string{}
	if *prefixExpand && len(results) > 0 {
		expandedPrefixes, err = prefixes.ExpandForRiskRecords(context.Background(), results, prefixes.RIPEConfig{Limit: *prefixLimit})
		if err != nil {
			if *prefixStrict {
				log.Fatalf("expand ASN prefixes: %v", err)
			}
			fmt.Fprintf(os.Stderr, "warning: prefix expansion failed: %v\n", err)
		}
		prefixes.ApplyCounts(results, expandedPrefixes)
	}
	stats = finalizeStats(stats, records, results, expandedPrefixes, startedAt)
	changes := history.BuildChanges(results, previousSnapshots, ts)

	if err := output.WriteArtifacts(*outputDir, results, changes, expandedPrefixes, stats); err != nil {
		log.Fatalf("write artifacts: %v", err)
	}
	if err := history.Update(*historyPath, *historyPath, results, ts, 90); err != nil {
		log.Fatalf("update history: %v", err)
	}
	if *readmePath != "" {
		if err := output.UpdateReadmeChangesTable(*readmePath, changes, ts, 25); err != nil {
			log.Fatalf("update readme changes table: %v", err)
		}
		if err := output.UpdateReadmeReleaseLinks(*readmePath, ts, *releaseURL); err != nil {
			log.Fatalf("update readme release links: %v", err)
		}
	}

	fmt.Fprintf(os.Stderr, "wrote %d ASN risk records to %s\n", len(results), *outputDir)
}

func initialStats(records []model.ObservedRecord, builtAt time.Time) model.BuildStats {
	stats := model.BuildStats{
		BuiltAt:      builtAt,
		InputRecords: len(records),
		TopSources:   map[string]int{},
	}
	for _, rec := range records {
		if rec.ASN != 0 {
			stats.RecordsWithASN++
		}
		if rec.Source != "" {
			stats.TopSources[rec.Source]++
		}
	}
	return stats
}

func finalizeStats(stats model.BuildStats, records []model.ObservedRecord, results []model.RiskRecord, expandedPrefixes map[int][]string, startedAt time.Time) model.BuildStats {
	stats.DurationSeconds = time.Since(startedAt).Seconds()
	stats.UniqueASNs = len(results)
	stats.ExpandedASNs = len(expandedPrefixes)
	for _, prefixes := range expandedPrefixes {
		stats.ExpandedPrefixes += len(prefixes)
	}
	sourceSet := map[string]bool{}
	for _, rec := range records {
		if rec.Source != "" {
			sourceSet[rec.Source] = true
		}
	}
	stats.UniqueSources = len(sourceSet)
	stats.CriticalCount = countLevel(results, "critical")
	stats.HighCount = countLevel(results, "high")
	stats.WatchCount = countLevel(results, "watch")
	stats.LowCount = countLevel(results, "low")
	stats.TopSources = limitStringCounts(stats.TopSources, 25)
	return stats
}

func countRecordsWithoutASN(records []model.ObservedRecord) int {
	n := 0
	for _, rec := range records {
		if rec.ASN == 0 {
			n++
		}
	}
	return n
}

func topUnmappedSamples(records []model.ObservedRecord, limit int) []string {
	seen := map[string]bool{}
	var out []string
	for _, rec := range records {
		if rec.ASN != 0 {
			continue
		}
		key := rec.IP
		if key == "" {
			key = rec.CIDR
		}
		if key == "" || seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, key)
		if len(out) >= limit {
			break
		}
	}
	return out
}

func countLevel(records []model.RiskRecord, level string) int {
	n := 0
	for _, rec := range records {
		if rec.RiskLevel == level {
			n++
		}
	}
	return n
}

func limitStringCounts(in map[string]int, limit int) map[string]int {
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

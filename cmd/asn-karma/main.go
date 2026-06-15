package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"asn-karma/internal/blackroute"
	"asn-karma/internal/enrich"
	"asn-karma/internal/model"
	"asn-karma/internal/output"
	"asn-karma/internal/scoring"
)

func main() {
	var (
		inputPath  = flag.String("input", "data/blackroute.jsonl", "path to BlackRoute JSONL")
		outputDir  = flag.String("out", "release", "directory for release artifacts")
		configPath = flag.String("config", "configs/scoring.json", "path to scoring config")
		readmePath = flag.String("readme", "", "optional README path to update with the latest ASN evidence table")
		releaseURL = flag.String("release-url", "https://github.com/ipanalytics/ASN-Karma/releases/latest/download", "base URL for README release artifact links")
		asnEnrich  = flag.Bool("asn-enrich", true, "enrich records without ASN using Team Cymru bulk whois")
		cymruAddr  = flag.String("cymru-addr", "whois.cymru.com:43", "Team Cymru whois address")
		cymruBatch = flag.Int("cymru-batch", 10000, "Team Cymru enrichment batch size")
		cymruLimit = flag.Int("cymru-limit", 0, "maximum unique IP/CIDR representatives to enrich; 0 means no limit")
		allowEmpty = flag.Bool("allow-empty", false, "allow a build that produces zero ASN risk records")
		builtAt    = flag.String("built-at", "", "override build timestamp in RFC3339 format")
	)
	flag.Parse()

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

	if *asnEnrich {
		stats, err := enrich.EnrichWithTeamCymru(context.Background(), records, enrich.CymruConfig{
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
			stats.RecordsNeedingASN,
			stats.UniqueQueries,
			stats.MappedQueries,
			stats.EnrichedRecords,
		)
	}

	aggregates := model.AggregateRecords(records)
	results := scoring.ScoreAll(context.Background(), cfg, aggregates, ts)
	if len(results) == 0 && !*allowEmpty {
		log.Fatalf("no ASN risk records produced after enrichment")
	}

	if err := output.WriteArtifacts(*outputDir, results, ts); err != nil {
		log.Fatalf("write artifacts: %v", err)
	}
	if *readmePath != "" {
		if err := output.UpdateReadmeEvidenceTable(*readmePath, results, ts, 25); err != nil {
			log.Fatalf("update readme evidence table: %v", err)
		}
		if err := output.UpdateReadmeReleaseLinks(*readmePath, ts, *releaseURL); err != nil {
			log.Fatalf("update readme release links: %v", err)
		}
	}

	fmt.Fprintf(os.Stderr, "wrote %d ASN risk records to %s\n", len(results), *outputDir)
}

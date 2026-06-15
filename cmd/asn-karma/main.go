package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"asn-karma/internal/blackroute"
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

	aggregates := model.AggregateRecords(records)
	results := scoring.ScoreAll(context.Background(), cfg, aggregates, ts)

	if err := output.WriteArtifacts(*outputDir, results, ts); err != nil {
		log.Fatalf("write artifacts: %v", err)
	}
	if *readmePath != "" {
		if err := output.UpdateReadmeEvidenceTable(*readmePath, results, ts, 25); err != nil {
			log.Fatalf("update readme evidence table: %v", err)
		}
	}

	fmt.Fprintf(os.Stderr, "wrote %d ASN risk records to %s\n", len(results), *outputDir)
}

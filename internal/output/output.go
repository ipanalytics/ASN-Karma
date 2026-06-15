package output

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"asn-karma/internal/model"
)

func WriteArtifacts(dir string, records []model.RiskRecord, builtAt time.Time) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	if err := writeJSONL(filepath.Join(dir, "asn-risk.jsonl"), records); err != nil {
		return err
	}
	if err := writeSummaryCSV(filepath.Join(dir, "asn-summary.csv"), records); err != nil {
		return err
	}
	if err := writeEvidenceTable(filepath.Join(dir, "asn-evidence-table.md"), records, builtAt, 50); err != nil {
		return err
	}
	if err := writeReleaseNotes(filepath.Join(dir, "release-notes.md"), records, builtAt); err != nil {
		return err
	}
	if err := writeASNList(filepath.Join(dir, "high-risk-asn-critical.txt"), records, "critical", builtAt); err != nil {
		return err
	}
	if err := writeASNList(filepath.Join(dir, "high-risk-asn-high.txt"), records, "high", builtAt); err != nil {
		return err
	}
	if err := writeASNList(filepath.Join(dir, "high-risk-asn-watch.txt"), records, "watch", builtAt); err != nil {
		return err
	}
	return writeStats(filepath.Join(dir, "run_stats.json"), records, builtAt)
}

func writeJSONL(path string, records []model.RiskRecord) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	enc := json.NewEncoder(f)
	for _, rec := range records {
		if err := enc.Encode(rec); err != nil {
			return err
		}
	}
	return nil
}

func writeSummaryCSV(path string, records []model.RiskRecord) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	w := csv.NewWriter(f)
	defer w.Flush()

	if err := w.Write([]string{"asn", "asn_name", "country", "risk_score", "risk_level", "observed_records", "source_count", "recommended_action"}); err != nil {
		return err
	}
	for _, rec := range records {
		if err := w.Write([]string{
			strconv.Itoa(rec.ASN),
			rec.ASNName,
			rec.Country,
			strconv.Itoa(rec.RiskScore),
			rec.RiskLevel,
			strconv.Itoa(rec.ObservedRecords),
			strconv.Itoa(rec.SourceCount),
			rec.RecommendedAction,
		}); err != nil {
			return err
		}
	}
	return w.Error()
}

func writeEvidenceTable(path string, records []model.RiskRecord, builtAt time.Time, limit int) error {
	table := renderEvidenceTable(records, builtAt, limit)
	return os.WriteFile(path, []byte(table), 0o644)
}

func UpdateReadmeEvidenceTable(path string, records []model.RiskRecord, builtAt time.Time, limit int) error {
	const start = "<!-- ASN_KARMA_TABLE_START -->"
	const end = "<!-- ASN_KARMA_TABLE_END -->"

	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	content := string(b)
	startIdx := strings.Index(content, start)
	endIdx := strings.Index(content, end)
	if startIdx == -1 || endIdx == -1 || endIdx < startIdx {
		return fmt.Errorf("README markers not found")
	}

	replacement := start + "\n" + renderEvidenceTable(records, builtAt, limit) + end
	updated := content[:startIdx] + replacement + content[endIdx+len(end):]
	return os.WriteFile(path, []byte(updated), 0o644)
}

func UpdateReadmeReleaseLinks(path string, builtAt time.Time, releaseBaseURL string) error {
	const start = "<!-- ASN_KARMA_RELEASE_START -->"
	const end = "<!-- ASN_KARMA_RELEASE_END -->"

	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	content := string(b)
	startIdx := strings.Index(content, start)
	endIdx := strings.Index(content, end)
	if startIdx == -1 || endIdx == -1 || endIdx < startIdx {
		return fmt.Errorf("README release markers not found")
	}

	replacement := start + "\n" + renderReleaseLinks(builtAt, releaseBaseURL) + end
	updated := content[:startIdx] + replacement + content[endIdx+len(end):]
	return os.WriteFile(path, []byte(updated), 0o644)
}

func writeReleaseNotes(path string, records []model.RiskRecord, builtAt time.Time) error {
	var b strings.Builder
	fmt.Fprintf(&b, "# ASN Karma Dataset\n\n")
	fmt.Fprintf(&b, "Built at `%s`.\n\n", builtAt.UTC().Format(time.RFC3339))
	fmt.Fprintf(&b, "| Metric | Value |\n")
	fmt.Fprintf(&b, "| --- | ---: |\n")
	fmt.Fprintf(&b, "| ASN records | %d |\n", len(records))
	fmt.Fprintf(&b, "| Critical | %d |\n", countLevel(records, "critical"))
	fmt.Fprintf(&b, "| High | %d |\n", countLevel(records, "high"))
	fmt.Fprintf(&b, "| Watch | %d |\n\n", countLevel(records, "watch"))
	b.WriteString("## Artifacts\n\n")
	b.WriteString("| File | Description |\n")
	b.WriteString("| --- | --- |\n")
	for _, artifact := range releaseArtifacts() {
		fmt.Fprintf(&b, "| `%s` | %s |\n", artifact.File, artifact.Description)
	}
	b.WriteString("\n## Top ASN Evidence\n\n")
	b.WriteString(renderEvidenceTable(records, builtAt, 25))
	return os.WriteFile(path, []byte(b.String()), 0o644)
}

func renderEvidenceTable(records []model.RiskRecord, builtAt time.Time, limit int) string {
	tableRecords := append([]model.RiskRecord(nil), records...)
	sort.Slice(tableRecords, func(i, j int) bool {
		if tableRecords[i].ObservedRecords == tableRecords[j].ObservedRecords {
			if tableRecords[i].RiskScore == tableRecords[j].RiskScore {
				return tableRecords[i].ASN < tableRecords[j].ASN
			}
			return tableRecords[i].RiskScore > tableRecords[j].RiskScore
		}
		return tableRecords[i].ObservedRecords > tableRecords[j].ObservedRecords
	})

	var b strings.Builder
	fmt.Fprintf(&b, "_Last updated: `%s`_\n\n", builtAt.UTC().Format(time.RFC3339))
	b.WriteString("| ASN | Name | Country | Evidence | Sources | Score | Tier |\n")
	b.WriteString("| --- | --- | --- | ---: | ---: | ---: | --- |\n")

	if limit <= 0 || limit > len(tableRecords) {
		limit = len(tableRecords)
	}
	for i := 0; i < limit; i++ {
		rec := tableRecords[i]
		country := rec.Country
		if country == "" {
			country = "-"
		}
		name := rec.ASNName
		if name == "" {
			name = "-"
		}
		fmt.Fprintf(
			&b,
			"| AS%d | %s | %s | %d | %d | %d | `%s` |\n",
			rec.ASN,
			escapeMarkdownCell(name),
			escapeMarkdownCell(country),
			rec.ObservedRecords,
			rec.SourceCount,
			rec.RiskScore,
			rec.RiskLevel,
		)
	}
	if len(records) == 0 {
		b.WriteString("| - | - | - | 0 | 0 | 0 | `none` |\n")
	}
	b.WriteString("\n")
	return b.String()
}

type releaseArtifact struct {
	File        string
	Description string
}

func releaseArtifacts() []releaseArtifact {
	return []releaseArtifact{
		{"asn-risk.jsonl", "Primary JSONL risk dataset"},
		{"asn-summary.csv", "CSV summary for review and reporting"},
		{"asn-evidence-table.md", "Markdown table of top ASN evidence counts"},
		{"high-risk-asn-critical.txt", "Critical ASN tier"},
		{"high-risk-asn-high.txt", "High ASN tier"},
		{"high-risk-asn-watch.txt", "Watch ASN tier"},
		{"release-notes.md", "Release summary and top ASN table"},
		{"run_stats.json", "Build metadata and tier counts"},
	}
}

func renderReleaseLinks(builtAt time.Time, releaseBaseURL string) string {
	releaseBaseURL = strings.TrimRight(releaseBaseURL, "/")

	var b strings.Builder
	fmt.Fprintf(&b, "_Last dataset build: `%s`_\n\n", builtAt.UTC().Format(time.RFC3339))
	b.WriteString("[Open latest GitHub release](https://github.com/ipanalytics/ASN-Karma/releases/latest)\n\n")
	b.WriteString("| Artifact | Download | Description |\n")
	b.WriteString("| --- | --- | --- |\n")
	for _, artifact := range releaseArtifacts() {
		fmt.Fprintf(
			&b,
			"| `%s` | [download](%s/%s) | %s |\n",
			artifact.File,
			releaseBaseURL,
			artifact.File,
			artifact.Description,
		)
	}
	b.WriteString("\n")
	return b.String()
}

func escapeMarkdownCell(s string) string {
	s = strings.ReplaceAll(s, "\\", "\\\\")
	s = strings.ReplaceAll(s, "|", "\\|")
	return s
}

func writeASNList(path string, records []model.RiskRecord, level string, builtAt time.Time) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	if _, err := fmt.Fprintf(f, "# ASN Karma %s tier\n# built_at=%s\n", level, builtAt.UTC().Format(time.RFC3339)); err != nil {
		return err
	}

	wrote := false
	for _, rec := range records {
		if rec.RiskLevel == level {
			if _, err := fmt.Fprintf(f, "AS%d\n", rec.ASN); err != nil {
				return err
			}
			wrote = true
		}
	}
	if !wrote {
		if _, err := f.WriteString("# no entries\n"); err != nil {
			return err
		}
	}
	return nil
}

func writeStats(path string, records []model.RiskRecord, builtAt time.Time) error {
	stats := map[string]any{
		"built_at":       builtAt,
		"asn_records":    len(records),
		"critical_count": countLevel(records, "critical"),
		"high_count":     countLevel(records, "high"),
		"watch_count":    countLevel(records, "watch"),
	}
	b, err := json.MarshalIndent(stats, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o644)
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

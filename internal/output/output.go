package output

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"asn-karma/internal/model"
)

func WriteArtifacts(dir string, records []model.RiskRecord, changes []model.ASNChange, expandedPrefixes map[int][]string, stats model.BuildStats) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	profileDir := filepath.Join(dir, "asn-profiles")
	_ = os.RemoveAll(profileDir)
	if err := os.MkdirAll(profileDir, 0o755); err != nil {
		return err
	}
	if err := writeJSONL(filepath.Join(dir, "asn-risk.jsonl"), records); err != nil {
		return err
	}
	if err := writeSummaryCSV(filepath.Join(dir, "asn-summary.csv"), records); err != nil {
		return err
	}
	if err := writeChangesJSONL(filepath.Join(dir, "asn-changes.jsonl"), changes); err != nil {
		return err
	}
	if err := writeSourceImpactCSV(filepath.Join(dir, "source-impact.csv"), records); err != nil {
		return err
	}
	if err := writeCountryRiskCSV(filepath.Join(dir, "country-risk.csv"), records); err != nil {
		return err
	}
	if err := writeEvidenceTable(filepath.Join(dir, "asn-evidence-table.md"), records, stats.BuiltAt, 50); err != nil {
		return err
	}
	if err := writeReport(filepath.Join(dir, "report.md"), records, changes, stats); err != nil {
		return err
	}
	if err := writeReleaseNotes(filepath.Join(dir, "release-notes.md"), records, changes, stats); err != nil {
		return err
	}
	if err := writeASNList(filepath.Join(dir, "high-risk-asn-critical.txt"), records, "critical", stats.BuiltAt); err != nil {
		return err
	}
	if err := writeASNList(filepath.Join(dir, "high-risk-asn-high.txt"), records, "high", stats.BuiltAt); err != nil {
		return err
	}
	if err := writeASNList(filepath.Join(dir, "high-risk-asn-watch.txt"), records, "watch", stats.BuiltAt); err != nil {
		return err
	}
	if err := writePrefixList(filepath.Join(dir, "high-risk-asn-prefixes-critical.txt"), records, expandedPrefixes, "critical", stats.BuiltAt); err != nil {
		return err
	}
	if err := writePrefixList(filepath.Join(dir, "high-risk-asn-prefixes-high.txt"), records, expandedPrefixes, "high", stats.BuiltAt); err != nil {
		return err
	}
	if err := writePrefixList(filepath.Join(dir, "high-risk-asn-prefixes-watch.txt"), records, expandedPrefixes, "watch", stats.BuiltAt); err != nil {
		return err
	}
	if err := writeProfiles(profileDir, records, expandedPrefixes); err != nil {
		return err
	}
	if err := writeProfilesArchive(filepath.Join(dir, "asn-profiles.tar.gz"), profileDir); err != nil {
		return err
	}
	if err := writeStats(filepath.Join(dir, "run_stats.json"), stats); err != nil {
		return err
	}
	if err := writeIndex(filepath.Join(dir, "index.json"), dir, stats); err != nil {
		return err
	}
	return writeChecksums(filepath.Join(dir, "checksums.txt"), dir)
}

func writeJSONL(path string, records []model.RiskRecord) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	enc := json.NewEncoder(f)
	if len(records) == 0 {
		return enc.Encode(map[string]any{
			"record_type": "build_status",
			"status":      "empty_asn_dataset",
			"message":     "no ASN records were produced from the current input; IP-to-ASN enrichment is required for upstream records without ASN fields",
		})
	}
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

	if err := w.Write([]string{"asn", "asn_name", "country", "risk_score", "risk_level", "confidence_score", "confidence", "review_required", "observed_records", "source_count", "active_days_30d", "trend", "evidence_delta_1d", "recommended_action"}); err != nil {
		return err
	}
	for _, rec := range records {
		if err := w.Write([]string{
			strconv.Itoa(rec.ASN),
			rec.ASNName,
			rec.Country,
			strconv.Itoa(rec.RiskScore),
			rec.RiskLevel,
			strconv.Itoa(rec.ConfidenceScore),
			rec.Confidence,
			strconv.FormatBool(rec.ReviewRequired),
			strconv.Itoa(rec.ObservedRecords),
			strconv.Itoa(rec.SourceCount),
			strconv.Itoa(rec.ActiveDays30D),
			rec.Trend,
			strconv.Itoa(rec.EvidenceDelta1D),
			rec.RecommendedAction,
		}); err != nil {
			return err
		}
	}
	return w.Error()
}

func writeChangesJSONL(path string, changes []model.ASNChange) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	enc := json.NewEncoder(f)
	if len(changes) == 0 {
		return enc.Encode(map[string]any{
			"record_type": "build_status",
			"status":      "no_asn_changes",
		})
	}
	for _, change := range changes {
		if err := enc.Encode(change); err != nil {
			return err
		}
	}
	return nil
}

func writeSourceImpactCSV(path string, records []model.RiskRecord) error {
	type impact struct {
		records  int
		asns     map[int]bool
		critical int
		high     int
		watch    int
	}
	bySource := map[string]*impact{}
	for _, rec := range records {
		for source, count := range rec.SourceBreakdown {
			item := bySource[source]
			if item == nil {
				item = &impact{asns: map[int]bool{}}
				bySource[source] = item
			}
			item.records += count
			item.asns[rec.ASN] = true
			switch rec.RiskLevel {
			case "critical":
				item.critical++
			case "high":
				item.high++
			case "watch":
				item.watch++
			}
		}
	}
	names := make([]string, 0, len(bySource))
	for name := range bySource {
		names = append(names, name)
	}
	sort.Slice(names, func(i, j int) bool {
		if bySource[names[i]].records == bySource[names[j]].records {
			return names[i] < names[j]
		}
		return bySource[names[i]].records > bySource[names[j]].records
	})

	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	w := csv.NewWriter(f)
	defer w.Flush()
	if err := w.Write([]string{"source", "records", "unique_asns", "critical_asns", "high_asns", "watch_asns"}); err != nil {
		return err
	}
	for _, name := range names {
		item := bySource[name]
		if err := w.Write([]string{name, strconv.Itoa(item.records), strconv.Itoa(len(item.asns)), strconv.Itoa(item.critical), strconv.Itoa(item.high), strconv.Itoa(item.watch)}); err != nil {
			return err
		}
	}
	return w.Error()
}

func writeCountryRiskCSV(path string, records []model.RiskRecord) error {
	type country struct {
		asns     int
		evidence int
		critical int
		high     int
		watch    int
		top      []model.RiskRecord
	}
	byCountry := map[string]*country{}
	for _, rec := range records {
		code := rec.Country
		if code == "" {
			code = "unknown"
		}
		item := byCountry[code]
		if item == nil {
			item = &country{}
			byCountry[code] = item
		}
		item.asns++
		item.evidence += rec.ObservedRecords
		switch rec.RiskLevel {
		case "critical":
			item.critical++
		case "high":
			item.high++
		case "watch":
			item.watch++
		}
		item.top = append(item.top, rec)
	}
	countries := make([]string, 0, len(byCountry))
	for code := range byCountry {
		countries = append(countries, code)
		sort.Slice(byCountry[code].top, func(i, j int) bool {
			if byCountry[code].top[i].ObservedRecords == byCountry[code].top[j].ObservedRecords {
				return byCountry[code].top[i].ASN < byCountry[code].top[j].ASN
			}
			return byCountry[code].top[i].ObservedRecords > byCountry[code].top[j].ObservedRecords
		})
	}
	sort.Slice(countries, func(i, j int) bool {
		if byCountry[countries[i]].evidence == byCountry[countries[j]].evidence {
			return countries[i] < countries[j]
		}
		return byCountry[countries[i]].evidence > byCountry[countries[j]].evidence
	})

	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	w := csv.NewWriter(f)
	defer w.Flush()
	if err := w.Write([]string{"country", "asn_count", "evidence_count", "critical_count", "high_count", "watch_count", "top_asns"}); err != nil {
		return err
	}
	for _, code := range countries {
		item := byCountry[code]
		top := make([]string, 0, min(5, len(item.top)))
		for i := 0; i < len(item.top) && i < 5; i++ {
			top = append(top, fmt.Sprintf("AS%d", item.top[i].ASN))
		}
		if err := w.Write([]string{code, strconv.Itoa(item.asns), strconv.Itoa(item.evidence), strconv.Itoa(item.critical), strconv.Itoa(item.high), strconv.Itoa(item.watch), strings.Join(top, " ")}); err != nil {
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

func writeReleaseNotes(path string, records []model.RiskRecord, changes []model.ASNChange, stats model.BuildStats) error {
	var b strings.Builder
	fmt.Fprintf(&b, "# ASN Karma Dataset - %s\n\n", stats.BuiltAt.UTC().Format("2006-01-02 15:04 UTC"))
	fmt.Fprintf(&b, "Built at `%s`.\n\n", stats.BuiltAt.UTC().Format(time.RFC3339))
	fmt.Fprintf(&b, "| Metric | Value |\n")
	fmt.Fprintf(&b, "| --- | ---: |\n")
	fmt.Fprintf(&b, "| Input records | %d |\n", stats.InputRecords)
	fmt.Fprintf(&b, "| Records enriched | %d |\n", stats.RecordsEnriched)
	fmt.Fprintf(&b, "| Records unmapped | %d |\n", stats.RecordsUnmapped)
	fmt.Fprintf(&b, "| Unique ASNs | %d |\n", stats.UniqueASNs)
	fmt.Fprintf(&b, "| Unique sources | %d |\n", stats.UniqueSources)
	fmt.Fprintf(&b, "| Expanded ASNs | %d |\n", stats.ExpandedASNs)
	fmt.Fprintf(&b, "| Expanded prefixes | %d |\n", stats.ExpandedPrefixes)
	fmt.Fprintf(&b, "| Critical | %d |\n", stats.CriticalCount)
	fmt.Fprintf(&b, "| High | %d |\n", stats.HighCount)
	fmt.Fprintf(&b, "| Watch | %d |\n", stats.WatchCount)
	fmt.Fprintf(&b, "| Duration seconds | %.2f |\n\n", stats.DurationSeconds)
	b.WriteString("## Artifacts\n\n")
	b.WriteString("| File | Description |\n")
	b.WriteString("| --- | --- |\n")
	for _, artifact := range releaseArtifacts() {
		fmt.Fprintf(&b, "| `%s` | %s |\n", artifact.File, artifact.Description)
	}
	b.WriteString("\n## Top ASN Evidence\n\n")
	b.WriteString(renderEvidenceTable(records, stats.BuiltAt, 25))
	b.WriteString("## Changes Since Previous Build\n\n")
	b.WriteString(renderChangesTable(changes, 20))
	return os.WriteFile(path, []byte(b.String()), 0o644)
}

func writeReport(path string, records []model.RiskRecord, changes []model.ASNChange, stats model.BuildStats) error {
	var b strings.Builder
	fmt.Fprintf(&b, "# ASN Karma Report - %s\n\n", stats.BuiltAt.UTC().Format("2006-01-02 15:04 UTC"))
	fmt.Fprintf(&b, "Built at `%s`.\n\n", stats.BuiltAt.UTC().Format(time.RFC3339))
	b.WriteString("## Build Health\n\n")
	fmt.Fprintf(&b, "| Metric | Value |\n| --- | ---: |\n")
	fmt.Fprintf(&b, "| Input records | %d |\n", stats.InputRecords)
	fmt.Fprintf(&b, "| Enriched records | %d |\n", stats.RecordsEnriched)
	fmt.Fprintf(&b, "| Unmapped records | %d |\n", stats.RecordsUnmapped)
	fmt.Fprintf(&b, "| Unique ASNs | %d |\n", stats.UniqueASNs)
	fmt.Fprintf(&b, "| Critical | %d |\n", stats.CriticalCount)
	fmt.Fprintf(&b, "| High | %d |\n", stats.HighCount)
	fmt.Fprintf(&b, "| Watch | %d |\n\n", stats.WatchCount)
	b.WriteString("## Top ASN Evidence\n\n")
	b.WriteString(renderEvidenceTable(records, stats.BuiltAt, 25))
	b.WriteString("## Biggest Changes\n\n")
	b.WriteString(renderChangesTable(changes, 25))
	b.WriteString("## Country Rollup\n\n")
	b.WriteString(renderCountryTable(records, 20))
	b.WriteString("## Source Impact\n\n")
	b.WriteString(renderSourceTable(records, 20))
	return os.WriteFile(path, []byte(b.String()), 0o644)
}

func renderChangesTable(changes []model.ASNChange, limit int) string {
	var b strings.Builder
	b.WriteString("| ASN | Change | Previous | Current | Evidence Delta |\n")
	b.WriteString("| --- | --- | ---: | ---: | ---: |\n")
	if len(changes) == 0 {
		b.WriteString("| - | no changes | 0 | 0 | 0 |\n\n")
		return b.String()
	}
	for i := 0; i < len(changes) && i < limit; i++ {
		change := changes[i]
		fmt.Fprintf(&b, "| AS%d | `%s` | %d | %d | %+d |\n", change.ASN, change.Change, change.PreviousEvidence, change.CurrentEvidence, change.EvidenceDelta)
	}
	b.WriteString("\n")
	return b.String()
}

func renderCountryTable(records []model.RiskRecord, limit int) string {
	type item struct {
		country  string
		asns     int
		evidence int
		critical int
		high     int
		watch    int
	}
	byCountry := map[string]*item{}
	for _, rec := range records {
		code := rec.Country
		if code == "" {
			code = "unknown"
		}
		entry := byCountry[code]
		if entry == nil {
			entry = &item{country: code}
			byCountry[code] = entry
		}
		entry.asns++
		entry.evidence += rec.ObservedRecords
		switch rec.RiskLevel {
		case "critical":
			entry.critical++
		case "high":
			entry.high++
		case "watch":
			entry.watch++
		}
	}
	items := make([]*item, 0, len(byCountry))
	for _, item := range byCountry {
		items = append(items, item)
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].evidence == items[j].evidence {
			return items[i].country < items[j].country
		}
		return items[i].evidence > items[j].evidence
	})
	var b strings.Builder
	b.WriteString("| Country | ASNs | Evidence | Critical | High | Watch |\n")
	b.WriteString("| --- | ---: | ---: | ---: | ---: | ---: |\n")
	if len(items) == 0 {
		b.WriteString("| - | 0 | 0 | 0 | 0 | 0 |\n\n")
		return b.String()
	}
	for i := 0; i < len(items) && i < limit; i++ {
		item := items[i]
		fmt.Fprintf(&b, "| %s | %d | %d | %d | %d | %d |\n", item.country, item.asns, item.evidence, item.critical, item.high, item.watch)
	}
	b.WriteString("\n")
	return b.String()
}

func renderSourceTable(records []model.RiskRecord, limit int) string {
	type item struct {
		source string
		count  int
		asns   map[int]bool
	}
	bySource := map[string]*item{}
	for _, rec := range records {
		for source, count := range rec.SourceBreakdown {
			entry := bySource[source]
			if entry == nil {
				entry = &item{source: source, asns: map[int]bool{}}
				bySource[source] = entry
			}
			entry.count += count
			entry.asns[rec.ASN] = true
		}
	}
	items := make([]*item, 0, len(bySource))
	for _, item := range bySource {
		items = append(items, item)
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].count == items[j].count {
			return items[i].source < items[j].source
		}
		return items[i].count > items[j].count
	})
	var b strings.Builder
	b.WriteString("| Source | Records | ASNs |\n")
	b.WriteString("| --- | ---: | ---: |\n")
	if len(items) == 0 {
		b.WriteString("| - | 0 | 0 |\n\n")
		return b.String()
	}
	for i := 0; i < len(items) && i < limit; i++ {
		item := items[i]
		fmt.Fprintf(&b, "| `%s` | %d | %d |\n", escapeMarkdownCell(item.source), item.count, len(item.asns))
	}
	b.WriteString("\n")
	return b.String()
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
	b.WriteString("| ASN | Name | Country | Evidence | Sources | Score | Tier | Review |\n")
	b.WriteString("| --- | --- | --- | ---: | ---: | ---: | --- | --- |\n")

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
			"| AS%d | %s | %s | %d | %d | %d | `%s` | %t |\n",
			rec.ASN,
			escapeMarkdownCell(name),
			escapeMarkdownCell(country),
			rec.ObservedRecords,
			rec.SourceCount,
			rec.RiskScore,
			rec.RiskLevel,
			rec.ReviewRequired,
		)
	}
	if len(records) == 0 {
		b.WriteString("| - | - | - | 0 | 0 | 0 | `none` | false |\n")
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
		{"index.json", "Machine-readable release manifest"},
		{"asn-risk.jsonl", "Primary JSONL risk dataset"},
		{"asn-changes.jsonl", "ASN delta feed since previous build"},
		{"asn-summary.csv", "CSV summary for review and reporting"},
		{"asn-evidence-table.md", "Markdown table of top ASN evidence counts"},
		{"asn-profiles.tar.gz", "Per-ASN JSON profiles"},
		{"source-impact.csv", "Source contribution breakdown"},
		{"country-risk.csv", "Country-level operational rollup"},
		{"high-risk-asn-critical.txt", "Critical ASN tier"},
		{"high-risk-asn-high.txt", "High ASN tier"},
		{"high-risk-asn-watch.txt", "Watch ASN tier"},
		{"high-risk-asn-prefixes-critical.txt", "Derived critical ASN announced prefixes"},
		{"high-risk-asn-prefixes-high.txt", "Derived high ASN announced prefixes"},
		{"high-risk-asn-prefixes-watch.txt", "Derived watch ASN announced prefixes"},
		{"report.md", "Markdown dataset report"},
		{"release-notes.md", "Release summary and top ASN table"},
		{"run_stats.json", "Build metadata and tier counts"},
		{"checksums.txt", "SHA256 checksums for release artifacts"},
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

func writePrefixList(path string, records []model.RiskRecord, expanded map[int][]string, level string, builtAt time.Time) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	if _, err := fmt.Fprintf(f, "# ASN Karma %s derived prefixes\n# built_at=%s\n# expanded_prefixes_are_evidence=false\n", level, builtAt.UTC().Format(time.RFC3339)); err != nil {
		return err
	}
	wrote := false
	for _, rec := range records {
		if rec.RiskLevel != level {
			continue
		}
		for _, prefix := range expanded[rec.ASN] {
			if _, err := fmt.Fprintf(f, "%s\n", prefix); err != nil {
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

func writeProfiles(dir string, records []model.RiskRecord, expanded map[int][]string) error {
	for _, rec := range records {
		profile := map[string]any{
			"risk":                  rec,
			"announced_prefixes":    expanded[rec.ASN],
			"prefixes_are_evidence": false,
		}
		b, err := json.MarshalIndent(profile, "", "  ")
		if err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(dir, fmt.Sprintf("AS%d.json", rec.ASN)), append(b, '\n'), 0o644); err != nil {
			return err
		}
	}
	if len(records) == 0 {
		return os.WriteFile(filepath.Join(dir, "EMPTY.json"), []byte("{\"status\":\"empty_asn_dataset\"}\n"), 0o644)
	}
	return nil
}

func writeProfilesArchive(path string, profileDir string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	gz := gzip.NewWriter(f)
	defer gz.Close()
	tw := tar.NewWriter(gz)
	defer tw.Close()

	entries, err := os.ReadDir(profileDir)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		fullPath := filepath.Join(profileDir, entry.Name())
		info, err := entry.Info()
		if err != nil {
			return err
		}
		header, err := tar.FileInfoHeader(info, "")
		if err != nil {
			return err
		}
		header.Name = filepath.Join("asn-profiles", entry.Name())
		if err := tw.WriteHeader(header); err != nil {
			return err
		}
		in, err := os.Open(fullPath)
		if err != nil {
			return err
		}
		if _, err := io.Copy(tw, in); err != nil {
			_ = in.Close()
			return err
		}
		if err := in.Close(); err != nil {
			return err
		}
	}
	return nil
}

func writeStats(path string, stats model.BuildStats) error {
	b, err := json.MarshalIndent(stats, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o644)
}

func writeIndex(path string, dir string, stats model.BuildStats) error {
	type artifact struct {
		Name   string `json:"name"`
		Size   int64  `json:"size"`
		SHA256 string `json:"sha256"`
	}
	index := struct {
		SchemaVersion string     `json:"schema_version"`
		BuiltAt       time.Time  `json:"built_at"`
		RecordCount   int        `json:"record_count"`
		Artifacts     []artifact `json:"artifacts"`
	}{
		SchemaVersion: "1.0",
		BuiltAt:       stats.BuiltAt,
		RecordCount:   stats.UniqueASNs,
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if entry.IsDir() || strings.HasPrefix(entry.Name(), ".") || entry.Name() == filepath.Base(path) || entry.Name() == "checksums.txt" {
			continue
		}
		fullPath := filepath.Join(dir, entry.Name())
		info, err := entry.Info()
		if err != nil {
			return err
		}
		sum, err := fileSHA256(fullPath)
		if err != nil {
			return err
		}
		index.Artifacts = append(index.Artifacts, artifact{
			Name:   entry.Name(),
			Size:   info.Size(),
			SHA256: fmt.Sprintf("%x", sum),
		})
	}
	sort.Slice(index.Artifacts, func(i, j int) bool {
		return index.Artifacts[i].Name < index.Artifacts[j].Name
	})
	b, err := json.MarshalIndent(index, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o644)
}

func writeChecksums(path string, dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	var lines []string
	for _, entry := range entries {
		if entry.IsDir() || strings.HasPrefix(entry.Name(), ".") || entry.Name() == filepath.Base(path) {
			continue
		}
		fullPath := filepath.Join(dir, entry.Name())
		sum, err := fileSHA256(fullPath)
		if err != nil {
			return err
		}
		lines = append(lines, fmt.Sprintf("%x  %s\n", sum, entry.Name()))
	}
	sort.Strings(lines)
	return os.WriteFile(path, []byte(strings.Join(lines, "")), 0o644)
}

func fileSHA256(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return nil, err
	}
	return h.Sum(nil), nil
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

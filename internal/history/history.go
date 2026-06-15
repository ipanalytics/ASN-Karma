package history

import (
	"bufio"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"time"

	"asn-karma/internal/model"
)

type Snapshot struct {
	Date            string `json:"date"`
	ASN             int    `json:"asn"`
	ObservedRecords int    `json:"observed_records"`
	RiskScore       int    `json:"risk_score"`
	RiskLevel       string `json:"risk_level"`
}

func BuildChanges(records []model.RiskRecord, previous map[int]Snapshot, builtAt time.Time) []model.ASNChange {
	changes := make([]model.ASNChange, 0)
	for _, rec := range records {
		prev := previous[rec.ASN]
		delta := rec.ObservedRecords - prev.ObservedRecords
		change := ""
		switch {
		case prev.ASN == 0:
			change = "new_asn"
		case prev.RiskLevel != rec.RiskLevel:
			change = "risk_level_changed"
		case delta > 0:
			change = "evidence_increased"
		case delta < 0:
			change = "evidence_decreased"
		default:
			continue
		}
		changes = append(changes, model.ASNChange{
			ASN:              rec.ASN,
			ASNName:          rec.ASNName,
			Country:          rec.Country,
			Change:           change,
			PreviousLevel:    prev.RiskLevel,
			CurrentLevel:     rec.RiskLevel,
			PreviousScore:    prev.RiskScore,
			CurrentScore:     rec.RiskScore,
			PreviousEvidence: prev.ObservedRecords,
			CurrentEvidence:  rec.ObservedRecords,
			EvidenceDelta:    delta,
			BuiltAt:          builtAt.UTC().Format(time.RFC3339),
		})
	}
	sort.Slice(changes, func(i, j int) bool {
		ai := abs(changes[i].EvidenceDelta)
		aj := abs(changes[j].EvidenceDelta)
		if ai == aj {
			return changes[i].ASN < changes[j].ASN
		}
		return ai > aj
	})
	return changes
}

func LoadLatestSnapshots(path string, builtAt time.Time) (map[int]Snapshot, error) {
	snapshots, err := readSnapshots(path)
	if err != nil {
		return nil, err
	}
	today := dateOnly(builtAt)
	out := map[int]Snapshot{}
	for _, snapshot := range snapshots {
		if snapshot.Date >= today {
			continue
		}
		prev, ok := out[snapshot.ASN]
		if !ok || snapshot.Date > prev.Date {
			out[snapshot.ASN] = snapshot
		}
	}
	return out, nil
}

func LoadSignals(path string, builtAt time.Time) (map[int]model.HistorySignal, error) {
	snapshots, err := readSnapshots(path)
	if err != nil {
		return nil, err
	}

	byASN := map[int][]Snapshot{}
	today := dateOnly(builtAt)
	for _, snapshot := range snapshots {
		if snapshot.Date >= today {
			continue
		}
		byASN[snapshot.ASN] = append(byASN[snapshot.ASN], snapshot)
	}

	signals := map[int]model.HistorySignal{}
	for asn, asnSnapshots := range byASN {
		sort.Slice(asnSnapshots, func(i, j int) bool {
			return asnSnapshots[i].Date < asnSnapshots[j].Date
		})
		first := asnSnapshots[0]
		last := asnSnapshots[len(asnSnapshots)-1]
		signal := model.HistorySignal{
			FirstSeen:       first.Date,
			LastSeen:        last.Date,
			PreviousRecords: last.ObservedRecords,
			Trend:           "new",
		}
		signal.ActiveDays7D = countActiveDays(asnSnapshots, today, 7)
		signal.ActiveDays30D = countActiveDays(asnSnapshots, today, 30)
		signal.ActiveDays90D = countActiveDays(asnSnapshots, today, 90)
		signals[asn] = signal
	}

	return signals, nil
}

func Update(path string, existingPath string, records []model.RiskRecord, builtAt time.Time, retentionDays int) error {
	if retentionDays <= 0 {
		retentionDays = 90
	}

	snapshots, err := readSnapshots(existingPath)
	if err != nil {
		return err
	}

	today := dateOnly(builtAt)
	filtered := make([]Snapshot, 0, len(snapshots)+len(records))
	for _, snapshot := range snapshots {
		if snapshot.Date == today {
			continue
		}
		if withinDays(snapshot.Date, today, retentionDays) {
			filtered = append(filtered, snapshot)
		}
	}
	for _, rec := range records {
		filtered = append(filtered, Snapshot{
			Date:            today,
			ASN:             rec.ASN,
			ObservedRecords: rec.ObservedRecords,
			RiskScore:       rec.RiskScore,
			RiskLevel:       rec.RiskLevel,
		})
	}
	sort.Slice(filtered, func(i, j int) bool {
		if filtered[i].Date == filtered[j].Date {
			return filtered[i].ASN < filtered[j].ASN
		}
		return filtered[i].Date < filtered[j].Date
	})

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	enc := json.NewEncoder(f)
	for _, snapshot := range filtered {
		if err := enc.Encode(snapshot); err != nil {
			return err
		}
	}
	return nil
}

func readSnapshots(path string) ([]Snapshot, error) {
	f, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()

	var snapshots []Snapshot
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64*1024), 8*1024*1024)
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var snapshot Snapshot
		if err := json.Unmarshal(line, &snapshot); err != nil {
			return nil, err
		}
		if snapshot.ASN != 0 && snapshot.Date != "" {
			snapshots = append(snapshots, snapshot)
		}
	}
	return snapshots, scanner.Err()
}

func countActiveDays(snapshots []Snapshot, today string, days int) int {
	seen := map[string]bool{}
	for _, snapshot := range snapshots {
		if withinDays(snapshot.Date, today, days) {
			seen[snapshot.Date] = true
		}
	}
	return len(seen)
}

func withinDays(date string, today string, days int) bool {
	d, err := time.Parse(time.DateOnly, date)
	if err != nil {
		return false
	}
	t, err := time.Parse(time.DateOnly, today)
	if err != nil {
		return false
	}
	cutoff := t.AddDate(0, 0, -(days - 1))
	return !d.Before(cutoff) && !d.After(t)
}

func dateOnly(t time.Time) string {
	return t.UTC().Format(time.DateOnly)
}

func abs(n int) int {
	if n < 0 {
		return -n
	}
	return n
}

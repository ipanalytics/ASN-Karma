package blackroute

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"strings"

	"asn-karma/internal/model"
)

// ReadJSONL accepts BlackRoute-style JSONL while tolerating small schema drift.
func ReadJSONL(path string) ([]model.ObservedRecord, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var out []model.ObservedRecord
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64*1024), 8*1024*1024)

	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		var raw map[string]any
		if err := json.Unmarshal([]byte(line), &raw); err != nil {
			return nil, fmt.Errorf("line %d: %w", lineNo, err)
		}

		rec := model.ObservedRecord{
			IP:           firstString(raw, "ip", "address", "addr"),
			CIDR:         firstString(raw, "cidr", "prefix", "network"),
			ASNName:      firstString(raw, "asn_name", "org", "organization"),
			Country:      strings.ToUpper(firstString(raw, "country", "country_code", "cc", "asn_country")),
			Source:       firstString(raw, "source", "feed", "provider"),
			ThreatLabels: stringSlice(raw, "threat_labels", "threat", "labels", "categories", "classification", "tags"),
		}
		rec.ASN = firstInt(raw, "asn", "as_number", "asn_number")

		if rec.CIDR == "" && rec.IP != "" {
			if addr, err := netip.ParseAddr(rec.IP); err == nil {
				if addr.Is4() {
					rec.CIDR = addr.String() + "/32"
				} else {
					rec.CIDR = addr.String() + "/128"
				}
			}
		}

		out = append(out, rec)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return out, nil
}

func firstString(raw map[string]any, keys ...string) string {
	for _, key := range keys {
		if v, ok := raw[key]; ok {
			switch x := v.(type) {
			case string:
				return strings.TrimSpace(x)
			case float64:
				return fmt.Sprintf("%.0f", x)
			}
		}
	}
	return ""
}

func firstInt(raw map[string]any, keys ...string) int {
	for _, key := range keys {
		if v, ok := raw[key]; ok {
			switch x := v.(type) {
			case float64:
				return int(x)
			case string:
				var n int
				if _, err := fmt.Sscanf(x, "%d", &n); err == nil {
					return n
				}
			}
		}
	}
	return 0
}

func stringSlice(raw map[string]any, keys ...string) []string {
	seen := map[string]bool{}
	var out []string
	for _, key := range keys {
		v, ok := raw[key]
		if !ok {
			continue
		}
		switch x := v.(type) {
		case string:
			for _, part := range strings.FieldsFunc(x, func(r rune) bool {
				return r == ',' || r == ';' || r == '|' || r == ' '
			}) {
				addString(&out, seen, part)
			}
		case []any:
			for _, item := range x {
				if s, ok := item.(string); ok {
					addString(&out, seen, s)
				}
			}
		}
	}
	return out
}

func addString(out *[]string, seen map[string]bool, s string) {
	s = strings.TrimSpace(strings.ToLower(s))
	if s == "" || seen[s] {
		return
	}
	seen[s] = true
	*out = append(*out, s)
}

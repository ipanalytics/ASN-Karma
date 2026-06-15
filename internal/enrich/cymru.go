package enrich

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"asn-karma/internal/model"
)

type CymruConfig struct {
	Address   string
	BatchSize int
	Timeout   time.Duration
	Limit     int
}

type CymruStats struct {
	RecordsNeedingASN int
	UniqueQueries     int
	MappedQueries     int
	EnrichedRecords   int
}

type cymruResult struct {
	ASN     int
	Prefix  string
	Country string
	ASNName string
}

func EnrichWithTeamCymru(ctx context.Context, records []model.ObservedRecord, cfg CymruConfig) (CymruStats, error) {
	if cfg.Address == "" {
		cfg.Address = "whois.cymru.com:43"
	}
	if cfg.BatchSize <= 0 {
		cfg.BatchSize = 10000
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 90 * time.Second
	}

	queryForRecord := make([]string, len(records))
	queries := map[string]bool{}
	stats := CymruStats{}

	for i, rec := range records {
		if rec.ASN != 0 {
			continue
		}
		stats.RecordsNeedingASN++

		query, ok := representativeIP(rec)
		if !ok {
			continue
		}
		queryForRecord[i] = query
		queries[query] = true
	}

	queryList := make([]string, 0, len(queries))
	for query := range queries {
		queryList = append(queryList, query)
	}
	sort.Strings(queryList)
	if cfg.Limit > 0 && len(queryList) > cfg.Limit {
		queryList = queryList[:cfg.Limit]
	}
	stats.UniqueQueries = len(queryList)

	results := map[string]cymruResult{}
	for start := 0; start < len(queryList); start += cfg.BatchSize {
		end := start + cfg.BatchSize
		if end > len(queryList) {
			end = len(queryList)
		}
		fmt.Fprintf(os.Stderr, "team cymru enrichment: querying %d-%d of %d\n", start+1, end, len(queryList))
		batchResults, err := queryCymruBatch(ctx, cfg.Address, cfg.Timeout, queryList[start:end])
		if err != nil {
			return stats, err
		}
		for query, result := range batchResults {
			results[query] = result
		}
	}
	stats.MappedQueries = len(results)

	for i := range records {
		if records[i].ASN != 0 {
			continue
		}
		result, ok := results[queryForRecord[i]]
		if !ok || result.ASN == 0 {
			continue
		}
		records[i].ASN = result.ASN
		if records[i].ASNName == "" {
			records[i].ASNName = result.ASNName
		}
		if records[i].Country == "" {
			records[i].Country = result.Country
		}
		if records[i].CIDR == "" && result.Prefix != "" {
			records[i].CIDR = result.Prefix
		}
		stats.EnrichedRecords++
	}

	return stats, nil
}

func representativeIP(rec model.ObservedRecord) (string, bool) {
	if rec.IP != "" {
		addr, err := netip.ParseAddr(rec.IP)
		if err == nil && addr.IsGlobalUnicast() {
			return addr.String(), true
		}
	}
	if rec.CIDR != "" {
		prefix, err := netip.ParsePrefix(rec.CIDR)
		if err == nil && prefix.Addr().IsGlobalUnicast() {
			return prefix.Addr().String(), true
		}
	}
	return "", false
}

func queryCymruBatch(ctx context.Context, address string, timeout time.Duration, queries []string) (map[string]cymruResult, error) {
	dialer := net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, fmt.Errorf("connect Team Cymru whois: %w", err)
	}
	defer conn.Close()

	deadline := time.Now().Add(timeout)
	_ = conn.SetDeadline(deadline)

	var request strings.Builder
	request.WriteString("begin\nverbose\n")
	for _, query := range queries {
		request.WriteString(query)
		request.WriteByte('\n')
	}
	request.WriteString("end\n")

	if _, err := io.WriteString(conn, request.String()); err != nil {
		return nil, fmt.Errorf("write Team Cymru whois request: %w", err)
	}

	results := map[string]cymruResult{}
	scanner := bufio.NewScanner(conn)
	scanner.Buffer(make([]byte, 64*1024), 8*1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "AS ") {
			continue
		}
		parts := strings.Split(line, "|")
		for i := range parts {
			parts[i] = strings.TrimSpace(parts[i])
		}
		if len(parts) < 7 || parts[0] == "NA" {
			continue
		}
		asn, err := strconv.Atoi(parts[0])
		if err != nil || asn == 0 {
			continue
		}
		ip := parts[1]
		results[ip] = cymruResult{
			ASN:     asn,
			Prefix:  parts[2],
			Country: strings.ToUpper(parts[3]),
			ASNName: parts[6],
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read Team Cymru whois response: %w", err)
	}

	return results, nil
}

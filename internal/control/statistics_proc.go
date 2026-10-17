package control

import (
	"bufio"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

const maxProtocolStatisticsBytes = 1 << 20

var statisticsFieldName = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]{0,127}$`)

func canonicalStatisticsValue(group, name, value string) (string, error) {
	if group == "Tcp" && name == "MaxConn" && value == "-1" {
		return value, nil
	}
	n, err := strconv.ParseUint(value, 10, 64)
	if err != nil || strconv.FormatUint(n, 10) != value {
		return "", fmt.Errorf("invalid statistics value for %s.%s", group, name)
	}
	return value, nil
}

func parseProtocolStatistics(data string, ipv6 bool) (map[string]map[string]string, error) {
	if len(data) > maxProtocolStatisticsBytes {
		return nil, fmt.Errorf("oversized protocol statistics")
	}
	result := map[string]map[string]string{}
	scanner := bufio.NewScanner(strings.NewReader(data))
	scanner.Buffer(make([]byte, 4096), 128*1024)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) == 0 {
			continue
		}
		if ipv6 {
			if len(fields) != 2 || !statisticsFieldName.MatchString(fields[0]) {
				return nil, fmt.Errorf("invalid IPv6 statistics line")
			}
			if result["IPv6"] == nil {
				result["IPv6"] = map[string]string{}
			}
			if _, duplicate := result["IPv6"][fields[0]]; duplicate {
				return nil, fmt.Errorf("duplicate IPv6 statistics field %s", fields[0])
			}
			value, err := canonicalStatisticsValue("IPv6", fields[0], fields[1])
			if err != nil {
				return nil, err
			}
			result["IPv6"][fields[0]] = value
			continue
		}
		if len(fields) < 2 || !strings.HasSuffix(fields[0], ":") {
			return nil, fmt.Errorf("invalid protocol statistics header")
		}
		group := strings.TrimSuffix(fields[0], ":")
		if !statisticsFieldName.MatchString(group) {
			return nil, fmt.Errorf("invalid protocol statistics group")
		}
		if _, duplicate := result[group]; duplicate {
			return nil, fmt.Errorf("duplicate statistics group %s", group)
		}
		if !scanner.Scan() {
			if err := scanner.Err(); err != nil {
				return nil, fmt.Errorf("read protocol statistics values: %w", err)
			}
			return nil, fmt.Errorf("missing statistics values for %s", group)
		}
		values := strings.Fields(scanner.Text())
		if len(values) != len(fields) || values[0] != fields[0] {
			return nil, fmt.Errorf("mismatched statistics values for %s", group)
		}
		result[group] = map[string]string{}
		for i, name := range fields[1:] {
			if !statisticsFieldName.MatchString(name) {
				return nil, fmt.Errorf("invalid statistics field %s", name)
			}
			if _, duplicate := result[group][name]; duplicate {
				return nil, fmt.Errorf("duplicate statistics field %s.%s", group, name)
			}
			value, err := canonicalStatisticsValue(group, name, values[i+1])
			if err != nil {
				return nil, err
			}
			result[group][name] = value
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read protocol statistics: %w", err)
	}
	if len(result) == 0 {
		return nil, fmt.Errorf("empty protocol statistics")
	}
	return result, nil
}

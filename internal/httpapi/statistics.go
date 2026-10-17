package httpapi

import (
	"errors"
	"fmt"
	"net/http"
	"strings"

	"netcontrol/internal/control"
)

var errStatisticsEndpointNotFound = errors.New("statistics endpoint not found")

func isStatisticsPath(path string) bool {
	return path == "/api/v1/statistics" || strings.HasPrefix(path, "/api/v1/statistics/")
}

func statisticsQuery(r *http.Request) (control.StatisticsQuery, error) {
	if r.URL.RawQuery != "" || r.URL.ForceQuery {
		return control.StatisticsQuery{}, fmt.Errorf("statistics endpoints do not accept query parameters")
	}
	switch r.URL.Path {
	case "/api/v1/statistics":
		return control.StatisticsQuery{Section: control.StatisticsAll}, nil
	case "/api/v1/statistics/interfaces":
		return control.StatisticsQuery{Section: control.StatisticsInterfaces}, nil
	case "/api/v1/statistics/protocols":
		return control.StatisticsQuery{Section: control.StatisticsProtocols}, nil
	default:
		prefix := "/api/v1/statistics/interfaces/"
		if !strings.HasPrefix(r.URL.Path, prefix) {
			return control.StatisticsQuery{}, errStatisticsEndpointNotFound
		}
		name := strings.TrimPrefix(r.URL.Path, prefix)
		if name == "" || strings.Contains(name, "/") {
			return control.StatisticsQuery{}, errStatisticsEndpointNotFound
		}
		query := control.StatisticsQuery{Section: control.StatisticsInterfaces, Interface: name}
		return query, query.Validate()
	}
}

package httpapi

func applianceServicePath(path, action string) string {
	for _, service := range []string{"ntp", "syslog", "vnstat"} {
		want := "/api/v1/services/" + service
		if action != "" {
			want += "/" + action
		}
		if path == want {
			return service
		}
	}
	return ""
}

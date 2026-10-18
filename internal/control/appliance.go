package control

import (
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"
)

type NTPConfig struct {
	Enabled bool     `json:"enabled"`
	Servers []string `json:"servers"`
}

type SyslogServer struct {
	Host      string `json:"host"`
	Port      int    `json:"port"`
	Transport string `json:"transport"`
}

type SyslogConfig struct {
	Enabled bool           `json:"enabled"`
	Servers []SyslogServer `json:"servers"`
}

type VNStatConfig struct {
	Enabled bool `json:"enabled"`
}

type ApplianceServiceStatus struct {
	Name              string     `json:"name"`
	Scope             string     `json:"scope"`
	State             string     `json:"state"`
	PID               int        `json:"pid,omitempty"`
	StartedAt         *time.Time `json:"started_at,omitempty"`
	DatabaseDirectory string     `json:"database_directory,omitempty"`
	Error             string     `json:"error,omitempty"`
}

func (c *Config) normalizeAppliance() {
	if c.NTP.Servers == nil {
		c.NTP.Servers = []string{}
	}
	if c.Syslog.Servers == nil {
		c.Syslog.Servers = []SyslogServer{}
	}
	slices.Sort(c.NTP.Servers)
	slices.SortFunc(c.Syslog.Servers, func(a, b SyslogServer) int {
		return strings.Compare(syslogServerKey(a), syslogServerKey(b))
	})
}

func syslogServerKey(s SyslogServer) string {
	return s.Transport + ":" + s.Host + ":" + strconv.Itoa(s.Port)
}

func validServerHost(host string) bool {
	if a, err := netip.ParseAddr(host); err == nil {
		return a.String() == host && !a.Is4In6() && a.Zone() == "" &&
			(a.IsGlobalUnicast() || a.IsLoopback())
	}
	if len(host) == 0 || len(host) > 253 || strings.ToLower(host) != host {
		return false
	}
	// A malformed numeric address must not be treated as a DNS name.
	if strings.Trim(host, "0123456789.") == "" {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, ch := range label {
			if !(ch >= 'a' && ch <= 'z' || ch >= '0' && ch <= '9' || ch == '-') {
				return false
			}
		}
	}
	return true
}

func (c Config) validateAppliance() error {
	if len(c.NTP.Servers) > 8 || c.NTP.Enabled && len(c.NTP.Servers) == 0 {
		return fmt.Errorf("NTP requires 1..8 servers when enabled, at most 8 when disabled")
	}
	seen := map[string]bool{}
	for _, host := range c.NTP.Servers {
		if !validServerHost(host) || seen[host] {
			return fmt.Errorf("invalid or duplicate NTP server %q", host)
		}
		seen[host] = true
	}
	if len(c.Syslog.Servers) > 8 || c.Syslog.Enabled && len(c.Syslog.Servers) == 0 {
		return fmt.Errorf("syslog requires 1..8 servers when enabled, at most 8 when disabled")
	}
	seen = map[string]bool{}
	for _, s := range c.Syslog.Servers {
		key := syslogServerKey(s)
		if !validServerHost(s.Host) || s.Port < 1 || s.Port > 65535 ||
			!slices.Contains([]string{"udp", "tcp", "tls"}, s.Transport) || seen[key] {
			return fmt.Errorf("invalid or duplicate syslog destination %q", key)
		}
		seen[key] = true
	}
	return nil
}

func applianceStatuses(c Config, enabledState, message string) []ApplianceServiceStatus {
	result := []ApplianceServiceStatus{
		{Name: "ntp", Scope: "host"}, {Name: "syslog", Scope: "host"},
		{Name: "vnstat-host", Scope: "host"}, {Name: "vnstat-managed", Scope: "managed"},
	}
	for i, enabled := range []bool{c.NTP.Enabled, c.Syslog.Enabled, c.VNStat.Enabled, c.VNStat.Enabled} {
		result[i].State = "disabled"
		if enabled {
			result[i].State, result[i].Error = enabledState, message
		}
	}
	return result
}

func applianceConfigurationText(name, runtime, data, backendLog, caFile string, c Config) string {
	q := strconv.Quote
	switch name {
	case "ntp":
		var b strings.Builder
		for _, host := range c.NTP.Servers {
			fmt.Fprintf(&b, "server %s iburst\n", host)
		}
		fmt.Fprintf(&b, "port 0\ncmdport 0\nbindcmdaddress %s\npidfile %s\nuser root\n", runtime+"/chrony.sock", runtime+"/chrony.pid")
		// Never step time: transaction deadlines and audit history use wall time.
		b.WriteString("leapsecmode slew\n")
		return b.String()
	case "syslog":
		var b strings.Builder
		b.WriteString("@version: 4.3\n@include \"scl.conf\"\noptions { use-dns(no); keep-hostname(yes); flush-lines(1); };\n")
		b.WriteString("source s_system { system(); internal(); };\n")
		fmt.Fprintf(&b, "source s_backend { file(%s follow-freq(1) flags(no-parse)); };\n", q(backendLog))
		b.WriteString("destination d_local { file(\"/var/log/messages\" perm(0640)); };\nlog { source(s_system); destination(d_local); };\n")
		for i, s := range c.Syslog.Servers {
			fmt.Fprintf(&b, "destination d%d { syslog(%s transport(%s) port(%d)", i, q(s.Host), q(s.Transport), s.Port)
			if address, err := netip.ParseAddr(s.Host); err == nil && address.Is6() {
				b.WriteString(" ip-protocol(6)")
			}
			if s.Transport == "tls" {
				fmt.Fprintf(&b, " tls(ca-file(%s) peer-verify(required-trusted))", q(caFile))
			}
			b.WriteString("); };\n")
			fmt.Fprintf(&b, "log { source(s_system); source(s_backend); destination(d%d); };\n", i)
		}
		return b.String()
	default:
		return fmt.Sprintf("DatabaseDir %s\nDaemonUser \"root\"\nDaemonGroup \"root\"\nAlwaysAddNewInterfaces 1\nCreateDirs 0\nUseUTC 1\nUpdateInterval 5\nPollInterval 5\nSaveInterval 1\nRescanDatabaseOnSave 1\n",
			q(data))
	}
}

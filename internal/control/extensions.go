package control

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
)

type VLAN struct {
	Parent string `json:"parent"`
	ID     int    `json:"id"`
}

type SoftflowdConfig struct {
	Name          string         `json:"name"`
	Enabled       bool           `json:"enabled"`
	Interface     string         `json:"interface"`
	Collector     string         `json:"collector"`
	ExportVersion int            `json:"export_version"`
	SamplingRate  int            `json:"sampling_rate"`
	MaxFlows      int            `json:"max_flows"`
	Snaplen       int            `json:"snaplen"`
	Promiscuous   bool           `json:"promiscuous"`
	CaptureFilter string         `json:"capture_filter,omitempty"`
	Timeouts      map[string]int `json:"timeouts"`
}

type ParentInterface struct {
	Name      string `json:"name"`
	Kind      string `json:"kind"`
	Index     int    `json:"index"`
	MAC       string `json:"mac"`
	MTU       int    `json:"mtu"`
	Up        bool   `json:"up"`
	Available bool   `json:"available"`
	Error     string `json:"error,omitempty"`
}

type SoftflowdStatus struct {
	Name      string     `json:"name"`
	State     string     `json:"state"`
	PID       int        `json:"pid,omitempty"`
	StartedAt *time.Time `json:"started_at,omitempty"`
	Error     string     `json:"error,omitempty"`
}

type RuntimeState struct {
	DHCPRelay []DHCPRelayStatus `json:"dhcp_relay"`
	Parents   []ParentInterface `json:"parent_interfaces"`
	Softflowd []SoftflowdStatus `json:"softflowd"`
	Error     string            `json:"error,omitempty"`
}

type RuntimeAdapter interface {
	Runtime(context.Context, Config) (RuntimeState, error)
	Resume(context.Context, Config) error
}

type LinuxOptions struct {
	DHCPRelayBinary           string
	DHCPRelayRuntimeDirectory string
	DHCPRelayUID              int
	DHCPRelayGID              int
	AllowHostTunables         bool
	ParentInterfaces          []string
	SoftflowdBinary           string
	RuntimeDirectory          string
	SoftflowdUID              int
	SoftflowdGID              int
	Logger                    *slog.Logger
}

var serviceNamePattern = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,32}$`)
var softflowdTimeouts = []string{"general", "tcp", "tcp.rst", "tcp.fin", "udp", "icmp", "maxlife", "expint"}

func validInterfaceName(name string) bool {
	return namePattern.MatchString(name) && name != "lo" && name != "." && name != ".."
}

func orderedInterfaces(interfaces []Interface) ([]Interface, error) {
	byName := make(map[string]Interface, len(interfaces))
	for _, link := range interfaces {
		byName[link.Name] = link
	}
	colors := map[string]int{}
	result := make([]Interface, 0, len(interfaces))
	identities := map[string]bool{}
	var visit func(Interface) error
	visit = func(link Interface) error {
		if colors[link.Name] == 1 {
			return fmt.Errorf("VLAN parent cycle at %s", link.Name)
		}
		if colors[link.Name] == 2 {
			return nil
		}
		colors[link.Name] = 1
		if link.VLAN != nil {
			identity := fmt.Sprintf("%s/%d", link.VLAN.Parent, link.VLAN.ID)
			if identities[identity] {
				return fmt.Errorf("duplicate VLAN parent/ID %s", identity)
			}
			identities[identity] = true
			if parent, exists := byName[link.VLAN.Parent]; exists {
				if parent.Kind == "wireguard" {
					return fmt.Errorf("WireGuard cannot be a VLAN parent")
				}
				if link.MTU > parent.MTU {
					return fmt.Errorf("VLAN %s MTU exceeds parent MTU", link.Name)
				}
				if err := visit(parent); err != nil {
					return err
				}
			}
		}
		colors[link.Name] = 2
		result = append(result, link)
		return nil
	}
	for _, link := range interfaces {
		if err := visit(link); err != nil {
			return nil, err
		}
	}
	return result, nil
}

func validateSoftflowd(configs []SoftflowdConfig) error {
	if len(configs) > 16 {
		return fmt.Errorf("at most 16 softflowd instances are supported")
	}
	names := map[string]bool{}
	for _, s := range configs {
		if !serviceNamePattern.MatchString(s.Name) || names[s.Name] {
			return fmt.Errorf("invalid or duplicate softflowd instance name %q", s.Name)
		}
		names[s.Name] = true
		if !validInterfaceName(s.Interface) {
			return fmt.Errorf("%s: invalid capture interface", s.Name)
		}
		collector, err := netip.ParseAddrPort(s.Collector)
		if err != nil || collector.Port() == 0 || collector.Addr().Is4In6() || collector.Addr().Zone() != "" ||
			(!collector.Addr().IsGlobalUnicast() && !collector.Addr().IsLoopback()) || collector.String() != s.Collector {
			return fmt.Errorf("%s: collector must be a canonical numeric unicast IP:port", s.Name)
		}
		if s.ExportVersion != 1 && s.ExportVersion != 5 && s.ExportVersion != 9 && s.ExportVersion != 10 {
			return fmt.Errorf("%s: export version must be 1, 5, 9, or 10 (IPFIX)", s.Name)
		}
		if s.SamplingRate < 1 || s.SamplingRate > 1000000 || s.MaxFlows < 1 || s.MaxFlows > 1000000 || s.Snaplen < 64 || s.Snaplen > 65535 {
			return fmt.Errorf("%s: sampling/max_flows must be 1..1000000 and snaplen 64..65535", s.Name)
		}
		if len(s.CaptureFilter) > 4096 || strings.ContainsAny(s.CaptureFilter, "\x00\r\n") {
			return fmt.Errorf("%s: capture filter must be one line, at most 4096 bytes, without NUL", s.Name)
		}
		for name, seconds := range s.Timeouts {
			if !slices.Contains(softflowdTimeouts, name) || seconds < 0 || seconds > 604800 ||
				(seconds == 0 && name == "general") {
				return fmt.Errorf("%s: invalid softflowd timeout %q", s.Name, name)
			}
		}
	}
	return nil
}

func softflowdArgs(s SoftflowdConfig, socket, pidfile string) []string {
	args := []string{"-d", "-i", s.Interface, "-n", s.Collector, "-v", strconv.Itoa(s.ExportVersion),
		"-P", "udp", "-s", strconv.Itoa(s.SamplingRate), "-m", strconv.Itoa(s.MaxFlows),
		"-C", strconv.Itoa(s.Snaplen), "-c", socket, "-p", pidfile}
	if !s.Promiscuous {
		args = append(args, "-N")
	}
	names := make([]string, 0, len(s.Timeouts))
	for name := range s.Timeouts {
		names = append(names, name)
	}
	slices.Sort(names)
	for _, name := range names {
		args = append(args, "-t", name+"="+strconv.Itoa(s.Timeouts[name]))
	}
	args = append(args, "--")
	if s.CaptureFilter != "" {
		args = append(args, s.CaptureFilter)
	}
	return args
}

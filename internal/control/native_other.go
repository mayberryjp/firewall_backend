//go:build !linux

package control

import "fmt"

func NewLinuxAdapter(namespace, keyDirectory string) (Adapter, error) {
	return nil, fmt.Errorf("native networking requires Linux; use the simulator on this platform")
}

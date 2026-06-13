//go:build windows

package collect

import "github.com/FlinnZee/breachhound/internal/core"

func init() { core.RegisterCollector(&network{}) }

// network gathers active TCP connections/listeners and their owning process.
type network struct{}

func (network) Name() string { return "network" }

type psConn struct {
	LocalAddress  string `json:"LocalAddress"`
	LocalPort     int    `json:"LocalPort"`
	RemoteAddress string `json:"RemoteAddress"`
	RemotePort    int    `json:"RemotePort"`
	State         string `json:"State"`
	OwningProcess int    `json:"OwningProcess"`
	ProcessName   string `json:"ProcessName"`
}

func (n network) Collect(ctx *core.Context) error {
	var raw []psConn
	script := `Get-NetTCPConnection | ForEach-Object {
  $pn = (Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName
  [pscustomobject]@{
    LocalAddress=$_.LocalAddress; LocalPort=$_.LocalPort;
    RemoteAddress=$_.RemoteAddress; RemotePort=$_.RemotePort;
    State=$_.State.ToString(); OwningProcess=$_.OwningProcess; ProcessName=$pn
  }
} | ConvertTo-Json -Compress -Depth 3`
	if err := psJSON(script, &raw); err != nil {
		return err
	}
	for _, r := range raw {
		ctx.Host.Connections = append(ctx.Host.Connections, core.Connection{
			Proto:       "tcp",
			LocalAddr:   r.LocalAddress,
			LocalPort:   r.LocalPort,
			RemoteAddr:  r.RemoteAddress,
			RemotePort:  r.RemotePort,
			State:       r.State,
			PID:         r.OwningProcess,
			ProcessName: r.ProcessName,
		})
	}
	return nil
}

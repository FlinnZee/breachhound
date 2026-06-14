//go:build windows

package collect

import "github.com/FlinnZee/breachhound/internal/core"

func init() { core.RegisterCollector(&accounts{}) }

// accounts enumerates local user accounts, whether they are enabled, their last
// logon, and Administrators-group membership.
type accounts struct{}

func (accounts) Name() string { return "accounts" }

func (a accounts) Collect(ctx *core.Context) error {
	var raw []struct {
		Name      string `json:"Name"`
		SID       string `json:"SID"`
		Enabled   bool   `json:"Enabled"`
		LastLogon string `json:"LastLogon"`
		Admin     bool   `json:"Admin"`
	}
	// Read the Administrators membership once, then project each local user.
	script := `$admins = @(Get-LocalGroupMember -Group 'Administrators' -ErrorAction SilentlyContinue | ForEach-Object { $_.Name })
Get-LocalUser | ForEach-Object {
  $n = $_.Name
  [pscustomobject]@{
    Name = $n
    SID = $_.SID.Value
    Enabled = [bool]$_.Enabled
    LastLogon = if ($_.LastLogon) { $_.LastLogon.ToString('yyyy-MM-dd HH:mm') } else { '' }
    Admin = [bool](($admins -contains "$env:COMPUTERNAME\$n") -or ($admins -contains $n))
  }
} | ConvertTo-Json -Compress -Depth 3`
	if err := psJSON(script, &raw); err != nil {
		ctx.Skip("accounts: " + err.Error())
		return nil
	}
	for _, u := range raw {
		ctx.Host.Users = append(ctx.Host.Users, core.LocalUser{
			Name:      u.Name,
			SID:       u.SID,
			Enabled:   u.Enabled,
			LastLogon: u.LastLogon,
			Admin:     u.Admin,
		})
	}
	return nil
}

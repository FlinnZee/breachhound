package core

import "time"

// Process is a single running process and the attributes detectors care about.
type Process struct {
	PID       int    `json:"pid"`
	PPID      int    `json:"ppid"`
	Name      string `json:"name"`
	Path      string `json:"path"`
	CmdLine   string `json:"cmdline"`
	User      string `json:"user,omitempty"`
	Signed    bool   `json:"signed"`
	Signature string `json:"signature,omitempty"` // signer / verification note
	SHA256    string `json:"sha256,omitempty"`    // hash of the on-disk image
}

// Connection is an active network connection or listener and its owning process.
type Connection struct {
	Proto       string `json:"proto"` // tcp / udp
	LocalAddr   string `json:"local_addr"`
	LocalPort   int    `json:"local_port"`
	RemoteAddr  string `json:"remote_addr,omitempty"`
	RemotePort  int    `json:"remote_port,omitempty"`
	State       string `json:"state,omitempty"`
	PID         int    `json:"pid"`
	ProcessName string `json:"process_name,omitempty"`
}

// PersistenceItem is one autostart/persistence mechanism (ASEP).
type PersistenceItem struct {
	Type     string `json:"type"`     // run_key, service, scheduled_task, ...
	Name     string `json:"name"`
	Command  string `json:"command"`  // image path / command line that executes
	Location string `json:"location"` // registry path, task path, etc.
	User     string `json:"user,omitempty"`
}

// Event is a single Windows event-log record, with its named EventData fields
// preserved so detectors (including Sigma) can match on them.
type Event struct {
	Channel  string            `json:"channel"`
	Provider string            `json:"provider,omitempty"`
	ID       int               `json:"id"`
	Time     string            `json:"time,omitempty"`
	Message  string            `json:"message,omitempty"`
	Data     map[string]string `json:"data,omitempty"`
}

// LocalUser is a local account and the attributes detectors care about.
type LocalUser struct {
	Name      string   `json:"name"`
	SID       string   `json:"sid,omitempty"`
	Enabled   bool     `json:"enabled"`
	LastLogon string   `json:"last_logon,omitempty"`
	Created   string   `json:"created,omitempty"`
	Groups    []string `json:"groups,omitempty"` // local groups the user belongs to
	Admin     bool     `json:"admin"`            // member of Administrators
}

// HostModel is the shared in-memory snapshot that collectors fill and
// detectors consume. One scan produces exactly one HostModel.
type HostModel struct {
	Hostname    string            `json:"hostname"`
	OS          string            `json:"os"`
	Elevated    bool              `json:"elevated"`
	CollectedAt time.Time         `json:"collected_at"`
	Processes   []Process         `json:"processes,omitempty"`
	Connections []Connection      `json:"connections,omitempty"`
	Persistence []PersistenceItem `json:"persistence,omitempty"`
	Users       []LocalUser       `json:"users,omitempty"`
	Events      []Event           `json:"events,omitempty"`
}

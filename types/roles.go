package types

// Role is the struct responsible for holding all information needed for a policy
type Role struct {
	ID         string `json:"id"`
	RemoteUser string `json:"remoteUser"`
	SourceIP   string `json:"sourceIP"`
	TargetIP   string `json:"targetIP"`
	Actions    string `json:"actions"`
}

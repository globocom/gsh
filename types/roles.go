package types

// Role is the struct responsible for holding all information needed for a policy
type Role struct {
	ID         string `json:"id"`
	RemoteUser string `json:"remote_user"`
	SourceIP   string `json:"user_ip"`
	TargetIP   string `json:"remote_host"`
	Actions    string `json:"actions"`
}

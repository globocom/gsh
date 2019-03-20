package types

// Policy is the struct responsible for holding all information needed for a policy
type Policy struct {
	ID         string `json:"id"`
	Team       string `json:"team"`
	RemoteUser string `json:"remoteUser"`
	SourceIP   string `json:"sourceIP"`
	TargetIP   string `json:"targetIP"`
	Actions    string `json:"actions"`
}

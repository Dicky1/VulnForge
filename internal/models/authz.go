package models

// AuthzSession describes one authenticated principal used by the authz diff engine.
type AuthzSession struct {
	Name     string `json:"name" yaml:"name"`         // e.g. "admin", "userA", "userB"
	Role     string `json:"role" yaml:"role"`         // logical role label
	Kind     string `json:"kind" yaml:"kind"`         // "bearer" or "cookie"
	Value    string `json:"value" yaml:"value"`       // token or cookie header value
	Priority int    `json:"priority" yaml:"priority"` // higher = more privileged
}

// AuthzMatrix is the user-supplied role matrix. Endpoints is the list of paths
// (relative to Origin) to probe with every session.
type AuthzMatrix struct {
	Origin    string         `json:"origin" yaml:"origin"`
	Sessions  []AuthzSession `json:"sessions" yaml:"sessions"`
	Endpoints []string       `json:"endpoints" yaml:"endpoints"`
}

// AuthzProbe captures the outcome of one request for one session on one endpoint.
type AuthzProbe struct {
	Session   string `json:"session"`
	Role      string `json:"role"`
	Endpoint  string `json:"endpoint"`
	Status    int    `json:"status"`
	BodyHash  string `json:"body_hash"`
	BodyLen   int    `json:"body_len"`
	Error     string `json:"error,omitempty"`
}

// AuthzFindingDetail is attached to a Finding's evidence for authz diffs.
type AuthzFindingDetail struct {
	Endpoint      string `json:"endpoint"`
	HighSession   string `json:"high_session"`
	LowSession    string `json:"low_session"`
	HighStatus    int    `json:"high_status"`
	LowStatus     int    `json:"low_status"`
	BodyMatch     bool   `json:"body_match"`
}

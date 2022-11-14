package permissions

import (
	"errors"
	"net"
	"strings"

	"github.com/casbin/casbin"
	gormadapter "github.com/casbin/gorm-adapter"
	"github.com/spf13/viper"
)

// Init creates and returns a new Enforcer
func Init(config viper.Viper) (*casbin.Enforcer, error) {
	a := gormadapter.NewAdapter("mysql", config.GetString("storage_uri"), true)
	m := casbin.NewModel()

	// Add user request definitions:
	m.AddDef("r", "r", "id, remoteuser, sourceip, targetip, actions, currentuser")

	// Add policy definition
	m.AddDef("p", "p", "id, remoteuser, sourceip, targetip, actions")

	// Add role definition
	m.AddDef("g", "g", "_, _")

	// Add policy effect
	// The policy effect bellow means that if there's any matched policy rule of "allow",
	// the final effect is allow (aka allow-override). "p.eft" is the effect for a
	// policy, it can be allow or deny. It's optional and the default value is allow.
	m.AddDef("e", "e", "some(where (p.eft == allow))")

	// Add matchers
	// Check more details at https://github.com/globocom/gsh/wiki/api-permissions
	m.AddDef(
		"m",
		"m",
		"(p.id == r.id) && "+
			"(p.remoteuser == '*' || r.remoteuser == p.remoteuser || ( p.remoteuser == '.' && r.remoteuser == r.currentuser) == true ) && "+
			"( ipMultipleMatch(r.sourceip, p.sourceip) ) && "+
			"( ipMultipleMatch(r.targetip, p.targetip) ) && "+
			"( p.actions == '*' || r.actions == p.actions )",
	)

	// Initiates a new enforcer
	e, err := casbin.NewEnforcerSafe(m, a)
	if err != nil {
		return nil, errors.New("init: Could not create new Enforcer")
	}

	e.SetModel(m)
	e.EnableAutoSave(true)

	// Enable multiples IP address as source or targets
	e.AddFunction("ipMultipleMatch", IPMultipleMatchFunc)

	// Reload policies from database before add admin policies
	err = e.LoadPolicy()
	if err != nil {
		return nil, errors.New("init: Could not load policies")
	}

	return e, nil
}

// IPMultipleMatch determines whether any of IP address in ip1 matches the pattern of any IP address in ip2, ip2 can be an IP address or a CIDR pattern.
func IPMultipleMatch(ips1 string, ips2 string) bool {
	anyMatch := false
	for _, ip2 := range strings.Split(ips2, ";") {
		for _, ip1 := range strings.Split(ips1, ";") {
			objIP1 := net.ParseIP(ip1)
			if objIP1 == nil {
				panic("invalid argument: ip1 in IPMultipleMatch() function is not an IP address.")
			}
			_, cidr, err := net.ParseCIDR(ip2)
			if err != nil {
				objIP2 := net.ParseIP(ip2)
				if objIP2 == nil {
					panic("invalid argument: ip2 in IPMultipleMatch() function is neither an IP address nor a CIDR.")
				}

				if objIP1.Equal(objIP2) {
					anyMatch = true
				}
			}

			if cidr.Contains(objIP1) {
				anyMatch = true
			}
		}
	}
	return anyMatch
}

// IPMultipleMatchFunc is the wrapper for IPMultipleMatch.
func IPMultipleMatchFunc(args ...interface{}) (interface{}, error) {
	ip1 := args[0].(string)
	ip2 := args[1].(string)

	return bool(IPMultipleMatch(ip1, ip2)), nil
}

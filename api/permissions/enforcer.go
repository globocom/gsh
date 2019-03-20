package permissions

import (
	"errors"
	"fmt"

	gormadapter "github.com/Krlier/gorm-adapter"
	"github.com/casbin/casbin"
	"github.com/spf13/viper"
)

// Init creates and returns a new Enforcer
func Init(config viper.Viper) (*casbin.Enforcer, error) {
	a := gormadapter.NewAdapter("mysql", config.GetString("storage_uri"), true)
	m := casbin.NewModel()

	// Add user request definitions:
	m.AddDef("r", "r", "id, team, remote_user, sourceip, targetip, actions")
	m.AddDef("r", "r", "user, role")

	// Add policy definition
	m.AddDef("p", "p", "id, team, remote_user, sourceip, targetip, actions")
	m.AddDef("p", "p", "user, role")

	// Add role definition
	m.AddDef("g", "g", "_, _")

	// Add policy effect
	// The policy effect bellow means that if there's any matched policy rule of "allow",
	// the final effect is allow (aka allow-override). "p.eft" is the effect for a
	// policy, it can be allow or deny. It's optional and the default value is allow.
	m.AddDef("e", "e", "some(where (p.eft == allow))")

	// Add matchers
	m.AddDef("m", "m", "p.id == r.id && g(r.team, p.team) && r.remote_user == p.remote_user && ipMatch(r.sourceip,p.sourceip) && ipMatch(r.targetip, p.targetip)")
	m.AddDef("m", "m", "g(r.user, p.user) && r.role == p.role")

	// Initiates a new enforcer
	e, err := casbin.NewEnforcerSafe(m, a)
	if err != nil {
		return nil, errors.New("Could not create new Enforcer")
	}
	e.SetModel(m)
	e.EnableAutoSave(true)

	// Reload policies from database before add admin policies
	err = e.LoadPolicy()
	if err != nil {
		return nil, errors.New("Could not load policies")
	}

	// AddPolicySafe(requestPolicy.ID, requestPolicy.Team, requestPolicy.RemoteUser, requestPolicy.SourceIP, requestPolicy.TargetIP, requestPolicy.Actions)
	check, err := e.AddPolicySafe("admin", "*", "*", "0.0.0.0/0", "0.0.0.0/0", "*")
	if err != nil {
		return nil, err
	}
	if err == nil && check == false {
		fmt.Printf("Casbin admin policy alread exists\n")
	}
	check = e.AddRoleForUser(config.GetString("perm_admin"), "admin")
	if !check {
		fmt.Printf("GSH admin (%s) alread have admin policy\n", config.GetString("perm_admin"))
	}
	e.EnableLog(true)

	return e, nil
}

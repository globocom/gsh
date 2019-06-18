package permissions

import (
	"errors"

	gormadapter "github.com/Krlier/gorm-adapter"
	"github.com/casbin/casbin"
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
			"( ipMatch(r.sourceip, p.sourceip) ) && "+
			"( ipMatch(r.targetip, p.targetip) ) && "+
			"( p.actions == '*' || r.actions == p.actions )",
	)

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

	return e, nil
}

package handlers

import (
	"fmt"
	"net/http"
	"reflect"
	"regexp"

	"github.com/google/uuid"

	"github.com/labstack/echo"
)

// Policy is the struct responsible for holding all information needed for a policy
type Policy struct {
	ID         string `json:"id"`
	Team       string `json:"team"`
	RemoteUser string `json:"remoteUser"`
	SourceIP   string `json:"sourceIP"`
	TargetIP   string `json:"targetIP"`
	Actions    string `json:"actions"`
}

// getField returns the value of a field in a token or error if the field doesn't exist
func getField(token *IDToken, field string) (string, error) {
	r := reflect.ValueOf(token)
	f := reflect.Indirect(r).FieldByName(field)
	result := f.String()
	if result == "<invalid Value>" {
		return "", fmt.Errorf("getField: Field (%s) not found at IDToken", field)
	}
	return result, nil
}

// GetPolicies prints all the existing policies
func (h AppHandler) GetPolicies(c echo.Context) error {
	// Validates JWT token before any other action
	token, err := ValidateJWT(c, h.config)
	if err != nil {
		return c.JSON(http.StatusUnauthorized,
			map[string]string{"result": "fail", "message": "Failed validating JWT", "details": err.Error()})
	}
	field := h.config.GetString("oidc_claim")
	username, err := getField(&token, field)
	if err != nil {
		return c.JSON(http.StatusInternalServerError,
			map[string]string{"result": "fail", "message": "The field declared in oidc_claim doesn't exist", "details": err.Error()})
	}

	permissions := h.permEnforcer.GetPermissionsForUser(username)

	return c.JSON(http.StatusOK, map[string][][]string{"policies": permissions})
}

// AddPolicies adds a new policy
func (h AppHandler) AddPolicies(c echo.Context) error {
	// Validates JWT token before any other action
	token, err := ValidateJWT(c, h.config)
	if err != nil {
		return c.JSON(http.StatusUnauthorized,
			map[string]string{"result": "fail", "message": "Failed validating JWT", "details": err.Error()})
	}

	// Validates if the user creating the policy has permission to do so
	field := h.config.GetString("oidc_claim")
	username, err := getField(&token, field)
	if err != nil {
		return c.JSON(http.StatusInternalServerError,
			map[string]string{"result": "fail", "message": "The field declared in oidc_claim doesn't exist", "details": err.Error()})
	}
	if username != h.config.GetString("perm_admin") {
		return c.JSON(http.StatusForbidden,
			map[string]string{"result": "fail", "message": "This user can't create policies"})
	}

	// Binds the read policy to the "policy" variable
	permEnforcer := h.permEnforcer
	policy := new(Policy)
	if err = c.Bind(policy); err != nil {
		return c.JSON(http.StatusInternalServerError,
			map[string]string{"result": "fail", "message": "Failed creating new policy", "details": err.Error()})
	}
	// Creates uuid for the new policy
	uuid := uuid.New()
	policy.ID = uuid.String()

	// Validates if the IPs read are in a valid format
	re, _ := regexp.Compile(`^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$`)
	if !re.MatchString(policy.SourceIP) {
		return c.JSON(http.StatusBadRequest,
			map[string]string{"result": "fail", "message": "Invalid SourceIP format"})
	}
	if !re.MatchString(policy.TargetIP) {
		return c.JSON(http.StatusBadRequest,
			map[string]string{"result": "fail", "message": "Invalid TargetIP format"})
	}

	// Adds policy if not existent
	check, err := permEnforcer.AddPolicySafe(policy.ID, policy.Team, policy.RemoteUser, policy.SourceIP, policy.TargetIP, policy.Actions)
	if err != nil {
		return c.JSON(http.StatusInternalServerError,
			map[string]string{"result": "fail", "message": "Error adding new policy", "details": err.Error()})
	}
	if !check {
		return c.JSON(http.StatusConflict,
			map[string]string{"result": "fail", "message": "This policy already exists"})
	}

	return c.JSON(http.StatusOK, map[string]string{"result": "success", "message": "Policy created"})
}

// RemovePolicies removes an existent policy
func (h AppHandler) RemovePolicies(c echo.Context) error {
	// Validates JWT token before any other action
	token, err := ValidateJWT(c, h.config)
	if err != nil {
		return c.JSON(http.StatusUnauthorized,
			map[string]string{"result": "fail", "message": "Failed validating JWT", "details": err.Error()})
	}

	// Validates if the user deleting the policy has permission to do so
	field := h.config.GetString("oidc_claim")
	username, err := getField(&token, field)
	if err != nil {
		return c.JSON(http.StatusInternalServerError,
			map[string]string{"result": "fail", "message": "The field declared in oidc_claim doesn't exist", "details": err.Error()})
	}
	if username != h.config.GetString("perm_admin") {
		return c.JSON(http.StatusForbidden,
			map[string]string{"result": "fail", "message": "This user can't delete policies"})
	}

	//

	// Binds the read policy to the "policy" variable
	permEnforcer := h.permEnforcer
	policy := new(Policy)
	if err = c.Bind(policy); err != nil {
		return c.JSON(http.StatusInternalServerError,
			map[string]string{"result": "fail", "message": "Failed creating new policy", "details": err.Error()})
	}

	// Removes policy if found
	check, err := permEnforcer.RemovePolicySafe(policy.ID, policy.Team, policy.RemoteUser, policy.SourceIP, policy.TargetIP, policy.Actions)
	if !check {
		return c.JSON(http.StatusConflict,
			map[string]string{"result": "fail", "message": "Policy not found", "details": err.Error()})
	}

	return c.JSON(http.StatusOK, map[string]string{"result": "success", "message": "Policy removed"})
}

// Por último, a verificação utilizando e.Enforce()

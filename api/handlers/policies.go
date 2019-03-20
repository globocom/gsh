package handlers

import (
	"fmt"
	"net"
	"net/http"
	"reflect"

	"github.com/globocom/gsh/types"

	"github.com/labstack/echo"
)

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

// GetRolesForMe prints all the existing policies
func (h AppHandler) GetRolesForMe(c echo.Context) error {
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

	// permissions := h.permEnforcer.GetPolicy()
	h.permEnforcer.LoadPolicy()
	myRoles := h.permEnforcer.GetRolesForUser(username)
	allRoles := h.permEnforcer.GetPolicy()

	var forMeRoles []types.Policy
	for _, role := range allRoles {
		for _, myRole := range myRoles {
			if role[0] == myRole {
				forMeRoles = append(forMeRoles, types.Policy{
					ID:         role[0],
					Team:       role[1],
					RemoteUser: role[2],
					SourceIP:   role[3],
					TargetIP:   role[4],
					Actions:    role[5],
				})
			}
		}
	}

	return c.JSON(http.StatusOK, map[string]interface{}{"result": "success", "roles": forMeRoles})
}

// GetRoles prints all the existing roles
func (h AppHandler) GetRoles(c echo.Context) error {
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
	if username != h.config.GetString("perm_admin") {
		return c.JSON(http.StatusForbidden,
			map[string]string{"result": "fail", "message": "This user can't list roles"})
	}

	h.permEnforcer.LoadPolicy()
	roles := h.permEnforcer.GetPolicy()

	var completedRoles []types.Policy
	for _, role := range roles {
		completedRoles = append(completedRoles, types.Policy{
			ID:         role[0],
			Team:       role[1],
			RemoteUser: role[2],
			SourceIP:   role[3],
			TargetIP:   role[4],
			Actions:    role[5],
		})
	}

	return c.JSON(http.StatusOK, map[string]interface{}{"result": "success", "roles": completedRoles})
}

// AddRoles adds a new role
func (h AppHandler) AddRoles(c echo.Context) error {
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
			map[string]string{"result": "fail", "message": "This user can't create roles"})
	}

	// Binds the read policy to the "policy" variable
	requestPolicy := new(types.Policy)
	if err = c.Bind(requestPolicy); err != nil {
		return c.JSON(http.StatusInternalServerError,
			map[string]string{"result": "fail", "message": "Failed creating new policy", "details": err.Error()})
	}
	// Checks for policy ID
	if requestPolicy.ID == "" {
		return c.JSON(http.StatusBadRequest,
			map[string]string{"result": "fail", "message": "Invalid ID", "details": err.Error()})
	}

	// Validates if the IPs read are in a valid format
	_, sorceIPNet, err := net.ParseCIDR(requestPolicy.SourceIP)
	if err != nil {
		return c.JSON(http.StatusBadRequest,
			map[string]string{"result": "fail", "message": "Invalid SourceIP format", "details": err.Error()})
	}
	_, targetIPNet, err := net.ParseCIDR(requestPolicy.TargetIP)
	if err != nil {
		return c.JSON(http.StatusBadRequest,
			map[string]string{"result": "fail", "message": "Invalid TargetIP format", "details": err.Error()})
	}
	requestPolicy.SourceIP = sorceIPNet.String()
	requestPolicy.TargetIP = targetIPNet.String()

	// Adds policy if not existent
	h.permEnforcer.LoadPolicy()
	check, err := h.permEnforcer.AddPolicySafe(requestPolicy.ID, requestPolicy.Team, requestPolicy.RemoteUser, requestPolicy.SourceIP, requestPolicy.TargetIP, requestPolicy.Actions)
	if err != nil {
		return c.JSON(http.StatusInternalServerError,
			map[string]string{"result": "fail", "message": "Error adding new policy", "details": err.Error()})
	}
	if !check {
		return c.JSON(http.StatusConflict,
			map[string]string{"result": "fail", "message": "This policy already exists"})
	}

	return c.JSON(http.StatusOK, map[string]string{"result": "success", "message": "Role created"})
}

// RemoveRole removes an existent policy
func (h AppHandler) RemoveRole(c echo.Context) error {
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
			map[string]string{"result": "fail", "message": "This user can't delete roles"})
	}

	removeRoleID := c.Param("role")

	// Checks if role exists
	h.permEnforcer.LoadPolicy()
	roles := h.permEnforcer.GetFilteredPolicy(0, removeRoleID)
	var roleFound bool
	var removeRole types.Policy
	for _, role := range roles {
		if role[0] == removeRoleID {
			roleFound = true
			removeRole = types.Policy{
				ID:         role[0],
				Team:       role[1],
				RemoteUser: role[2],
				SourceIP:   role[3],
				TargetIP:   role[4],
				Actions:    role[5],
			}
		}
	}

	if !roleFound {
		return c.JSON(http.StatusNotFound,
			map[string]string{"result": "fail", "message": "Role ID not found"})
	}

	// Removes policy if found
	check, err := h.permEnforcer.RemovePolicySafe(removeRole.ID, removeRole.Team, removeRole.RemoteUser, removeRole.SourceIP, removeRole.TargetIP, removeRole.Actions)
	if err != nil {
		return c.JSON(http.StatusInternalServerError,
			map[string]string{"result": "fail", "message": "Policy can not be removed", "details": err.Error()})
	}
	if err == nil && check == false {
		return c.JSON(http.StatusNotFound,
			map[string]string{"result": "fail", "message": "Role ID not found"})
	}

	return c.JSON(http.StatusOK, map[string]string{"result": "success", "message": "Role removed"})
}

// AssociateRoleToUser associates a role to a specific user
func (h AppHandler) AssociateRoleToUser(c echo.Context) error {
	// Validates JWT token before any other action
	token, err := ValidateJWT(c, h.config)
	if err != nil {
		return c.JSON(http.StatusUnauthorized,
			map[string]string{"result": "fail", "message": "Failed validating JWT", "details": err.Error()})
	}

	// Validates if the user associating the role has permission to do so
	field := h.config.GetString("oidc_claim")
	username, err := getField(&token, field)
	if err != nil {
		return c.JSON(http.StatusInternalServerError,
			map[string]string{"result": "fail", "message": "The field declared in oidc_claim doesn't exist", "details": err.Error()})
	}
	if username != h.config.GetString("perm_admin") {
		return c.JSON(http.StatusForbidden,
			map[string]string{"result": "fail", "message": "This user can't associate role to an user"})
	}

	roleID := c.Param("role")
	user := c.Param("user")

	// Checks if role exists
	h.permEnforcer.LoadPolicy()
	roles := h.permEnforcer.GetFilteredPolicy(0, roleID)
	var roleFound bool
	for _, role := range roles {
		if role[0] == roleID {
			roleFound = true
		}
	}

	if !roleFound {
		return c.JSON(http.StatusNotFound,
			map[string]string{"result": "fail", "message": "Role ID not found"})
	}

	// Add role to user if found
	check := h.permEnforcer.AddRoleForUser(user, roleID)
	if !check {
		fmt.Printf("User (%s) alread have this policy policy (%s)\n", user, roleID)
	}

	return c.JSON(http.StatusOK, map[string]string{"result": "success", "message": "Role associated"})
}

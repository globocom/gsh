package handlers

import (
	"fmt"
	"net"
	"net/http"
	"reflect"

	"github.com/globocom/gsh/types"

	"github.com/gosimple/slug"
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

// GetRolesForMe prints all the existing roles to current user
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
	err = h.permEnforcer.LoadPolicy()
	if err != nil {
		return c.JSON(http.StatusInternalServerError,
			map[string]string{"result": "fail", "message": "Error reading roles", "details": err.Error()})
	}
	myRoles := h.permEnforcer.GetRolesForUser(username)
	allRoles := h.permEnforcer.GetPolicy()

	forMeRoles := []types.Role{}
	for _, role := range allRoles {
		for _, myRole := range myRoles {
			if role[0] == myRole {
				forMeRoles = append(forMeRoles, types.Role{
					ID:         role[0],
					RemoteUser: role[1],
					SourceIP:   role[2],
					TargetIP:   role[3],
					Actions:    role[4],
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
	if !contains(h.config.GetStringSlice("perm_admin"), username) {
		return c.JSON(http.StatusForbidden,
			map[string]string{"result": "fail", "message": "This user can't list roles"})
	}

	err = h.permEnforcer.LoadPolicy()
	if err != nil {
		return c.JSON(http.StatusInternalServerError,
			map[string]string{"result": "fail", "message": "Error reading roles", "details": err.Error()})
	}
	roles := h.permEnforcer.GetPolicy()

	completedRoles := []types.Role{}
	for _, role := range roles {
		completedRoles = append(completedRoles, types.Role{
			ID:         role[0],
			RemoteUser: role[1],
			SourceIP:   role[2],
			TargetIP:   role[3],
			Actions:    role[4],
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

	// Validates if the user creating the role has permission to do so
	field := h.config.GetString("oidc_claim")
	username, err := getField(&token, field)
	if err != nil {
		return c.JSON(http.StatusInternalServerError,
			map[string]string{"result": "fail", "message": "The field declared in oidc_claim doesn't exist", "details": err.Error()})
	}
	if !contains(h.config.GetStringSlice("perm_admin"), username) {
		return c.JSON(http.StatusForbidden,
			map[string]string{"result": "fail", "message": "This user can't create roles"})
	}

	// Binds the read role to the "requestPolicy" variable
	requestPolicy := new(types.Role)
	if err = c.Bind(requestPolicy); err != nil {
		return c.JSON(http.StatusInternalServerError,
			map[string]string{"result": "fail", "message": "Failed creating new role", "details": err.Error()})
	}
	// Checks for role ID
	if requestPolicy.ID == "" {
		return c.JSON(http.StatusBadRequest,
			map[string]string{"result": "fail", "message": "Invalid ID", "details": err.Error()})
	}

	// Slugify requestPolicy.ID if necessary
	if !slug.IsSlug(requestPolicy.ID) {
		requestPolicy.ID = slug.Make(requestPolicy.ID)
	}

	// Checks if RoleID exists
	err = h.permEnforcer.LoadPolicy()
	if err != nil {
		return c.JSON(http.StatusInternalServerError,
			map[string]string{"result": "fail", "message": "Error reading roles", "details": err.Error()})
	}
	roles := h.permEnforcer.GetFilteredPolicy(0, requestPolicy.ID)
	var roleFound bool
	for _, role := range roles {
		if role[0] == requestPolicy.ID {
			roleFound = true
		}
	}
	if roleFound {
		return c.JSON(http.StatusBadRequest,
			map[string]string{"result": "fail", "message": "RoleID alread exists"})
	}

	// Validates if the IPs read are in a valid format
	_, sorceIPNet, err := net.ParseCIDR(requestPolicy.SourceIP)
	if err != nil {
		return c.JSON(http.StatusBadRequest,
			map[string]string{"result": "fail", "message": "Invalid UserIP format", "details": err.Error()})
	}
	_, targetIPNet, err := net.ParseCIDR(requestPolicy.TargetIP)
	if err != nil {
		return c.JSON(http.StatusBadRequest,
			map[string]string{"result": "fail", "message": "Invalid RemoteHost format", "details": err.Error()})
	}
	requestPolicy.SourceIP = sorceIPNet.String()
	requestPolicy.TargetIP = targetIPNet.String()

	// Adds role if not existent
	err = h.permEnforcer.LoadPolicy()
	if err != nil {
		return c.JSON(http.StatusInternalServerError,
			map[string]string{"result": "fail", "message": "Error reading roles", "details": err.Error()})
	}
	check, err := h.permEnforcer.AddPolicySafe(requestPolicy.ID, requestPolicy.RemoteUser, requestPolicy.SourceIP, requestPolicy.TargetIP, requestPolicy.Actions)
	if err != nil {
		return c.JSON(http.StatusInternalServerError,
			map[string]string{"result": "fail", "message": "Error adding new role", "details": err.Error()})
	}
	if !check {
		return c.JSON(http.StatusConflict,
			map[string]string{"result": "fail", "message": "This role already exists"})
	}

	return c.JSON(http.StatusOK, map[string]string{"result": "success", "message": "Role created"})
}

// RemoveRole removes an existent role
func (h AppHandler) RemoveRole(c echo.Context) error {
	// Validates JWT token before any other action
	token, err := ValidateJWT(c, h.config)
	if err != nil {
		return c.JSON(http.StatusUnauthorized,
			map[string]string{"result": "fail", "message": "Failed validating JWT", "details": err.Error()})
	}

	// Validates if the user deleting the role has permission to do so
	field := h.config.GetString("oidc_claim")
	username, err := getField(&token, field)
	if err != nil {
		return c.JSON(http.StatusInternalServerError,
			map[string]string{"result": "fail", "message": "The field declared in oidc_claim doesn't exist", "details": err.Error()})
	}
	if !contains(h.config.GetStringSlice("perm_admin"), username) {
		return c.JSON(http.StatusForbidden,
			map[string]string{"result": "fail", "message": "This user can't delete roles"})
	}

	removeRoleID := c.Param("role")

	// Checks if role exists
	err = h.permEnforcer.LoadPolicy()
	if err != nil {
		return c.JSON(http.StatusInternalServerError,
			map[string]string{"result": "fail", "message": "Error reading roles", "details": err.Error()})
	}
	roles := h.permEnforcer.GetFilteredPolicy(0, removeRoleID)
	var roleFound bool
	var removeRole types.Role
	for _, role := range roles {
		if role[0] == removeRoleID {
			roleFound = true
			removeRole = types.Role{
				ID:         role[0],
				RemoteUser: role[1],
				SourceIP:   role[2],
				TargetIP:   role[3],
				Actions:    role[4],
			}
		}
	}

	if !roleFound {
		return c.JSON(http.StatusNotFound,
			map[string]string{"result": "fail", "message": "Role ID not found"})
	}

	// Removes role if found
	check, err := h.permEnforcer.RemovePolicySafe(removeRole.ID, removeRole.RemoteUser, removeRole.SourceIP, removeRole.TargetIP, removeRole.Actions)
	if err != nil {
		return c.JSON(http.StatusInternalServerError,
			map[string]string{"result": "fail", "message": "Role can not be removed", "details": err.Error()})
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
	if !contains(h.config.GetStringSlice("perm_admin"), username) {
		return c.JSON(http.StatusForbidden,
			map[string]string{"result": "fail", "message": "This user can't associate role to an user"})
	}

	roleID := c.Param("role")
	user := c.Param("user")

	// Checks if role exists
	err = h.permEnforcer.LoadPolicy()
	if err != nil {
		return c.JSON(http.StatusInternalServerError,
			map[string]string{"result": "fail", "message": "Error reading roles", "details": err.Error()})
	}
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
		fmt.Printf("User (%s) alread have this role (%s)\n", user, roleID)
	}

	return c.JSON(http.StatusOK, map[string]string{"result": "success", "message": "Role associated"})
}

// GetRolesByUser prints all the existing roles to specific user
func (h AppHandler) GetRolesByUser(c echo.Context) error {
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
	if !contains(h.config.GetStringSlice("perm_admin"), username) {
		return c.JSON(http.StatusForbidden,
			map[string]string{"result": "fail", "message": "This user can't list roles to anothers user"})
	}

	user := c.Param("user")

	// permissions := h.permEnforcer.GetPolicy()
	err = h.permEnforcer.LoadPolicy()
	if err != nil {
		return c.JSON(http.StatusInternalServerError,
			map[string]string{"result": "fail", "message": "Error reading roles", "details": err.Error()})
	}
	myRoles := h.permEnforcer.GetRolesForUser(user)
	allRoles := h.permEnforcer.GetPolicy()

	forUserRoles := []types.Role{}
	for _, role := range allRoles {
		for _, myRole := range myRoles {
			if role[0] == myRole {
				forUserRoles = append(forUserRoles, types.Role{
					ID:         role[0],
					RemoteUser: role[1],
					SourceIP:   role[2],
					TargetIP:   role[3],
					Actions:    role[4],
				})
			}
		}
	}

	return c.JSON(http.StatusOK, map[string]interface{}{"result": "success", "roles": forUserRoles})
}

// DisassociateRoleToUser disassociates a role to a specific user
func (h AppHandler) DisassociateRoleToUser(c echo.Context) error {
	// Validates JWT token before any other action
	token, err := ValidateJWT(c, h.config)
	if err != nil {
		return c.JSON(http.StatusUnauthorized,
			map[string]string{"result": "fail", "message": "Failed validating JWT", "details": err.Error()})
	}

	// Validates if the user disassociating the role has permission to do so
	field := h.config.GetString("oidc_claim")
	username, err := getField(&token, field)
	if err != nil {
		return c.JSON(http.StatusInternalServerError,
			map[string]string{"result": "fail", "message": "The field declared in oidc_claim doesn't exist", "details": err.Error()})
	}
	if !contains(h.config.GetStringSlice("perm_admin"), username) {
		return c.JSON(http.StatusForbidden,
			map[string]string{"result": "fail", "message": "This user can't disassociate role to an user"})
	}

	roleID := c.Param("role")
	user := c.Param("user")

	// Checks if role exists
	err = h.permEnforcer.LoadPolicy()
	if err != nil {
		return c.JSON(http.StatusInternalServerError,
			map[string]string{"result": "fail", "message": "Error reading roles", "details": err.Error()})
	}
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
	check := h.permEnforcer.DeleteRoleForUser(user, roleID)
	if !check {
		fmt.Printf("User (%s) don't have this role (%s)\n", user, roleID)
	}

	return c.JSON(http.StatusOK, map[string]string{"result": "success", "message": "Role disassociated"})
}

// GetUsersWithRole prints all associated users to specific role
func (h AppHandler) GetUsersWithRole(c echo.Context) error {
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
	if !contains(h.config.GetStringSlice("perm_admin"), username) {
		return c.JSON(http.StatusForbidden,
			map[string]string{"result": "fail", "message": "This user can't list roles to anothers user"})
	}

	role := c.Param("role")

	// permissions := h.permEnforcer.GetPolicy()
	err = h.permEnforcer.LoadPolicy()
	if err != nil {
		return c.JSON(http.StatusInternalServerError,
			map[string]string{"result": "fail", "message": "Error reading roles", "details": err.Error()})
	}
	users := h.permEnforcer.GetUsersForRole(role)
	roles := h.permEnforcer.GetPolicy()

	found := false
	finishRole := types.Role{}
	for _, currentRole := range roles {
		if currentRole[0] == role {
			finishRole = types.Role{
				ID:         currentRole[0],
				RemoteUser: currentRole[1],
				SourceIP:   currentRole[2],
				TargetIP:   currentRole[3],
				Actions:    currentRole[4],
			}
			found = true
		}
	}

	if !found {
		return c.JSON(http.StatusNotFound,
			map[string]string{"result": "fail", "message": "Role not found"})
	}

	return c.JSON(http.StatusOK, map[string]interface{}{"result": "success", "users": users, "role": finishRole})
}

// Contains tells whether a contains x.
func contains(a []string, x string) bool {
	for _, n := range a {
		if x == n {
			return true
		}
	}
	return false
}

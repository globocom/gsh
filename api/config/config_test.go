package config

import (
	"os"
	"testing"
)

func TestInit(t *testing.T) {
	t.Run(
		"Test Init()",
		func(t *testing.T) {
			config := Init()
			if os.Getenv("PORT") != "8000" {
				t.Fatalf("CONFIG: fail to set default port")
			}
			if len(config.GetString("storage_uri")) == 0 {
				t.Fatalf("CONFIG: fail to set default storage_uri")
			}
		})
}

func TestCheck(t *testing.T) {
	t.Run(
		"Test Check(): app port",
		func(t *testing.T) {

			config := Init()

			os.Unsetenv("PORT")
			err := Check(config)
			if err == nil {
				t.Fatalf("CONFIG: fail to check app port (%v)", err)
			}
		})
	t.Run(
		"Test Check(): storage_driver",
		func(t *testing.T) {

			os.Setenv("PORT", "8888")
			os.Unsetenv("GSH_STORAGE_DRIVER")
			config := Init()
			err := Check(config)
			if err == nil {
				t.Fatalf("CONFIG: fail to check app storage_driver (%v)", err)
			}
		})
	t.Run(
		"Test Check(): storage_uri",
		func(t *testing.T) {

			os.Setenv("PORT", "8888")
			os.Setenv("GSH_STORAGE_DRIVER", "mysql")
			os.Setenv("GSH_STORAGE_URI", "")
			config := Init()
			err := Check(config)
			if err == nil {
				t.Fatalf("CONFIG: fail to check app storage_uri (%v)", err)
			}
		})
	t.Run(
		"Test Check(): ca_external",
		func(t *testing.T) {

			os.Setenv("PORT", "8888")
			os.Setenv("GSH_STORAGE_DRIVER", "mysql")
			os.Setenv("GSH_CA_EXTERNAL", "1")
			config := Init()
			err := Check(config)
			if err == nil {
				t.Fatalf("CONFIG: fail to check app ca_external (%v)", err)
			}
		})
	t.Run(
		"Test Check(): ca_signer_url",
		func(t *testing.T) {

			os.Setenv("PORT", "8888")
			os.Setenv("GSH_STORAGE_DRIVER", "mysql")
			os.Setenv("GSH_CA_EXTERNAL", "1")
			os.Setenv("GSH_CA_SIGNER_URL", "/sign")
			config := Init()
			err := Check(config)
			if err == nil {
				t.Fatalf("CONFIG: fail to check app ca_signer_url (%v)", err)
			}
		})
	t.Run(
		"Test Check(): ca_public_key_url",
		func(t *testing.T) {

			os.Setenv("PORT", "8888")
			os.Setenv("GSH_STORAGE_DRIVER", "mysql")
			os.Setenv("GSH_CA_EXTERNAL", "1")
			os.Setenv("GSH_CA_SIGNER_URL", "/sign")
			os.Setenv("GSH_CA_PUBLIC_KEY", "GSH_CA_PUBLIC_KEY")
			config := Init()
			err := Check(config)
			if err == nil {
				t.Fatalf("CONFIG: fail to check app ca_public_key_url (%v)", err)
			}
		})
	t.Run(
		"Test Check(): ca_endpoint",
		func(t *testing.T) {

			os.Setenv("PORT", "8888")
			os.Setenv("GSH_STORAGE_DRIVER", "mysql")
			os.Setenv("GSH_CA_EXTERNAL", "1")
			os.Setenv("GSH_CA_SIGNER_URL", "/sign")
			os.Setenv("GSH_CA_PUBLIC_KEY", "GSH_CA_PUBLIC_KEY")
			os.Setenv("GSH_CA_ENDPOINT", "https://vault.example.org")
			config := Init()
			err := Check(config)
			if err == nil {
				t.Fatalf("CONFIG: fail to check app ca_endpoint (%v)", err)
			}
		})
	t.Run(
		"Test Check(): ca_role_id",
		func(t *testing.T) {

			os.Setenv("PORT", "8888")
			os.Setenv("GSH_STORAGE_DRIVER", "mysql")
			os.Setenv("GSH_CA_EXTERNAL", "1")
			os.Setenv("GSH_CA_SIGNER_URL", "/sign")
			os.Setenv("GSH_CA_PUBLIC_KEY", "GSH_CA_PUBLIC_KEY")
			os.Setenv("GSH_CA_ENDPOINT", "https://vault.example.org")
			os.Setenv("GSH_CA_ROLE_ID", "000000-0000-0000-0000")
			config := Init()
			err := Check(config)
			if err == nil {
				t.Fatalf("CONFIG: fail to check app ca_role_id (%v)", err)
			}
		})
	t.Run(
		"Test Check(): ca_external_secret_id",
		func(t *testing.T) {

			os.Setenv("PORT", "8888")
			os.Setenv("GSH_STORAGE_DRIVER", "mysql")
			os.Setenv("GSH_CA_EXTERNAL", "1")
			os.Setenv("GSH_CA_SIGNER_URL", "/sign")
			os.Setenv("GSH_CA_PUBLIC_KEY", "GSH_CA_PUBLIC_KEY")
			os.Setenv("GSH_CA_ENDPOINT", "https://vault.example.org")
			os.Setenv("GSH_CA_ROLE_ID", "000000-0000-0000-0000")
			os.Setenv("GSH_CA_EXTERNAL_SECRET_ID", "000000-0000-0000-0000")
			config := Init()
			err := Check(config)
			if err == nil {
				t.Fatalf("CONFIG: fail to check app ca_external_secret_id (%v)", err)
			}
		})
	t.Run(
		"Test Check(): ca_private_key",
		func(t *testing.T) {

			os.Setenv("PORT", "8888")
			os.Setenv("GSH_STORAGE_DRIVER", "mysql")
			os.Setenv("GSH_CA_EXTERNAL", "0")
			os.Setenv("GSH_CA_PRIVATE_KEY", "GSH_CA_PRIVATE_KEY")
			os.Setenv("GSH_CA_PUBLIC_KEY", "GSH_CA_PUBLIC_KEY")
			config := Init()
			err := Check(config)
			if err == nil {
				t.Fatalf("CONFIG: fail to check app ca_private_key (%v)", err)
			}
		})
	t.Run(
		"Test Check(): oidc_base_url",
		func(t *testing.T) {

			os.Setenv("PORT", "8888")
			os.Setenv("GSH_STORAGE_DRIVER", "mysql")
			os.Setenv("GSH_CA_EXTERNAL", "0")
			os.Setenv("GSH_CA_PRIVATE_KEY", "GSH_CA_PRIVATE_KEY")
			os.Setenv("GSH_CA_PUBLIC_KEY", "GSH_CA_PUBLIC_KEY")
			os.Setenv("GSH_OIDC_BASE_URL", "https://keycloak.example.org/auth/realms")
			config := Init()
			err := Check(config)
			if err == nil {
				t.Fatalf("CONFIG: fail to check app oidc_base_url (%v)", err)
			}
		})
	t.Run(
		"Test Check(): oidc_realm",
		func(t *testing.T) {

			os.Setenv("PORT", "8888")
			os.Setenv("GSH_STORAGE_DRIVER", "mysql")
			os.Setenv("GSH_CA_EXTERNAL", "0")
			os.Setenv("GSH_CA_PRIVATE_KEY", "GSH_CA_PRIVATE_KEY")
			os.Setenv("GSH_CA_PUBLIC_KEY", "GSH_CA_PUBLIC_KEY")
			os.Setenv("GSH_OIDC_BASE_URL", "https://keycloak.example.org/auth/realms")
			os.Setenv("GSH_OIDC_REALM", "gsh")
			config := Init()
			err := Check(config)
			if err == nil {
				t.Fatalf("CONFIG: fail to check app oidc_realm (%v)", err)
			}
		})
	t.Run(
		"Test Check(): oidc_audience",
		func(t *testing.T) {

			os.Setenv("PORT", "8888")
			os.Setenv("GSH_STORAGE_DRIVER", "mysql")
			os.Setenv("GSH_CA_EXTERNAL", "0")
			os.Setenv("GSH_CA_PRIVATE_KEY", "GSH_CA_PRIVATE_KEY")
			os.Setenv("GSH_CA_PUBLIC_KEY", "GSH_CA_PUBLIC_KEY")
			os.Setenv("GSH_OIDC_BASE_URL", "https://keycloak.example.org/auth/realms")
			os.Setenv("GSH_OIDC_REALM", "gsh")
			os.Setenv("GSH_OIDC_AUDIENCE", "gsh")
			config := Init()
			err := Check(config)
			if err == nil {
				t.Fatalf("CONFIG: fail to check app oidc_audience (%v)", err)
			}
		})
	t.Run(
		"Test Check(): oidc_authorized_party",
		func(t *testing.T) {

			os.Setenv("PORT", "8888")
			os.Setenv("GSH_STORAGE_DRIVER", "mysql")
			os.Setenv("GSH_CA_EXTERNAL", "0")
			os.Setenv("GSH_CA_PRIVATE_KEY", "GSH_CA_PRIVATE_KEY")
			os.Setenv("GSH_CA_PUBLIC_KEY", "GSH_CA_PUBLIC_KEY")
			os.Setenv("GSH_OIDC_BASE_URL", "https://keycloak.example.org/auth/realms")
			os.Setenv("GSH_OIDC_REALM", "gsh")
			os.Setenv("GSH_OIDC_AUTHORIZED_PARTY", "gsh")
			config := Init()
			err := Check(config)
			if err == nil {
				t.Fatalf("CONFIG: fail to check app oidc_authorized_party (%v)", err)
			}
		})
	t.Run(
		"Test Check(): oidc_claim",
		func(t *testing.T) {

			os.Setenv("PORT", "8888")
			os.Setenv("GSH_STORAGE_DRIVER", "mysql")
			os.Setenv("GSH_CA_EXTERNAL", "0")
			os.Setenv("GSH_CA_PRIVATE_KEY", "GSH_CA_PRIVATE_KEY")
			os.Setenv("GSH_CA_PUBLIC_KEY", "GSH_CA_PUBLIC_KEY")
			os.Setenv("GSH_OIDC_BASE_URL", "https://keycloak.example.org/auth/realms")
			os.Setenv("GSH_OIDC_REALM", "gsh")
			os.Setenv("GSH_OIDC_AUDIENCE", "gsh")
			os.Setenv("GSH_OIDC_AUTHORIZED_PARTY", "gsh")
			os.Setenv("GSH_OIDC_CLAIM", "PreferredUsername")
			config := Init()
			err := Check(config)
			if err == nil {
				t.Fatalf("CONFIG: fail to check app oidc_claim (%v)", err)
			}
		})
	t.Run(
		"Test Check(): oidc_claim_name",
		func(t *testing.T) {

			os.Setenv("PORT", "8888")
			os.Setenv("GSH_STORAGE_DRIVER", "mysql")
			os.Setenv("GSH_CA_EXTERNAL", "0")
			os.Setenv("GSH_CA_PRIVATE_KEY", "GSH_CA_PRIVATE_KEY")
			os.Setenv("GSH_CA_PUBLIC_KEY", "GSH_CA_PUBLIC_KEY")
			os.Setenv("GSH_OIDC_BASE_URL", "https://keycloak.example.org/auth/realms")
			os.Setenv("GSH_OIDC_REALM", "gsh")
			os.Setenv("GSH_OIDC_AUDIENCE", "gsh")
			os.Setenv("GSH_OIDC_AUTHORIZED_PARTY", "gsh")
			os.Setenv("GSH_OIDC_CLAIM", "PreferredUsername")
			os.Setenv("GSH_OIDC_CLAIM_NAME", "preferred_username")
			config := Init()
			err := Check(config)
			if err == nil {
				t.Fatalf("CONFIG: fail to check app oidc_claim_name (%v)", err)
			}
		})
	t.Run(
		"Test Check(): oidc_issuer",
		func(t *testing.T) {

			os.Setenv("PORT", "8888")
			os.Setenv("GSH_STORAGE_DRIVER", "mysql")
			os.Setenv("GSH_CA_EXTERNAL", "0")
			os.Setenv("GSH_CA_PRIVATE_KEY", "GSH_CA_PRIVATE_KEY")
			os.Setenv("GSH_CA_PUBLIC_KEY", "GSH_CA_PUBLIC_KEY")
			os.Setenv("GSH_OIDC_BASE_URL", "https://keycloak.example.org/auth/realms")
			os.Setenv("GSH_OIDC_REALM", "gsh")
			os.Setenv("GSH_OIDC_AUDIENCE", "gsh")
			os.Setenv("GSH_OIDC_AUTHORIZED_PARTY", "gsh")
			os.Setenv("GSH_OIDC_CLAIM", "PreferredUsername")
			os.Setenv("GSH_OIDC_CLAIM_NAME", "preferred_username")
			os.Setenv("GSH_OIDC_ISSUER", "https://keycloak.example.org/auth/realms")
			config := Init()
			err := Check(config)
			if err == nil {
				t.Fatalf("CONFIG: fail to check app oidc_issuer (%v)", err)
			}
		})
	t.Run(
		"Test Check(): oidc_certs",
		func(t *testing.T) {

			os.Setenv("PORT", "8888")
			os.Setenv("GSH_STORAGE_DRIVER", "mysql")
			os.Setenv("GSH_CA_EXTERNAL", "0")
			os.Setenv("GSH_CA_PRIVATE_KEY", "GSH_CA_PRIVATE_KEY")
			os.Setenv("GSH_CA_PUBLIC_KEY", "GSH_CA_PUBLIC_KEY")
			os.Setenv("GSH_OIDC_BASE_URL", "https://keycloak.example.org/auth/realms")
			os.Setenv("GSH_OIDC_REALM", "gsh")
			os.Setenv("GSH_OIDC_AUDIENCE", "gsh")
			os.Setenv("GSH_OIDC_AUTHORIZED_PARTY", "gsh")
			os.Setenv("GSH_OIDC_CLAIM", "PreferredUsername")
			os.Setenv("GSH_OIDC_CLAIM_NAME", "preferred_username")
			os.Setenv("GSH_OIDC_ISSUER", "https://keycloak.example.org/auth/realms")
			os.Setenv("GSH_OIDC_CERTS", "https://keycloak.example.org/.well-known/jwks.json")
			config := Init()
			err := Check(config)
			if err == nil {
				t.Fatalf("CONFIG: fail to check app oidc_certs (%v)", err)
			}
		})
	t.Run(
		"Test Check(): oidc_callback_port",
		func(t *testing.T) {

			os.Setenv("PORT", "8888")
			os.Setenv("GSH_STORAGE_DRIVER", "mysql")
			os.Setenv("GSH_CA_EXTERNAL", "0")
			os.Setenv("GSH_CA_PRIVATE_KEY", "GSH_CA_PRIVATE_KEY")
			os.Setenv("GSH_CA_PUBLIC_KEY", "GSH_CA_PUBLIC_KEY")
			os.Setenv("GSH_OIDC_BASE_URL", "https://keycloak.example.org/auth/realms")
			os.Setenv("GSH_OIDC_REALM", "gsh")
			os.Setenv("GSH_OIDC_AUDIENCE", "gsh")
			os.Setenv("GSH_OIDC_AUTHORIZED_PARTY", "gsh")
			os.Setenv("GSH_OIDC_CLAIM", "PreferredUsername")
			os.Setenv("GSH_OIDC_CLAIM_NAME", "preferred_username")
			os.Setenv("GSH_OIDC_ISSUER", "https://keycloak.example.org/auth/realms")
			os.Setenv("GSH_OIDC_CERTS", "https://keycloak.example.org/.well-known/jwks.json")
			os.Setenv("GSH_OIDC_CALLBACK_PORT", "30000")
			config := Init()
			err := Check(config)
			if err == nil {
				t.Fatalf("CONFIG: fail to check app oidc_callback_port (%v)", err)
			}
		})
	t.Run(
		"Test Check(): perm_admin - last test",
		func(t *testing.T) {

			os.Setenv("PORT", "8888")
			os.Setenv("GSH_STORAGE_DRIVER", "mysql")
			os.Setenv("GSH_CA_EXTERNAL", "0")
			os.Setenv("GSH_CA_PRIVATE_KEY", "GSH_CA_PRIVATE_KEY")
			os.Setenv("GSH_CA_PUBLIC_KEY", "GSH_CA_PUBLIC_KEY")
			os.Setenv("GSH_OIDC_BASE_URL", "https://keycloak.example.org/auth/realms")
			os.Setenv("GSH_OIDC_REALM", "gsh")
			os.Setenv("GSH_OIDC_AUDIENCE", "gsh")
			os.Setenv("GSH_OIDC_AUTHORIZED_PARTY", "gsh")
			os.Setenv("GSH_OIDC_CLAIM", "PreferredUsername")
			os.Setenv("GSH_OIDC_CLAIM_NAME", "preferred_username")
			os.Setenv("GSH_OIDC_ISSUER", "https://keycloak.example.org/auth/realms")
			os.Setenv("GSH_OIDC_CERTS", "https://keycloak.example.org/.well-known/jwks.json")
			os.Setenv("GSH_OIDC_CALLBACK_PORT", "30000")
			os.Setenv("GSH_PERM_ADMIN", "admin admin1 admin2")
			config := Init()
			err := Check(config)
			if err != nil {
				t.Fatalf("CONFIG: fail to check app perm_admin (%v)", err)
			}
		})
}

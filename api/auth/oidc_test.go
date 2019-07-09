package auth

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/labstack/echo"
	"github.com/spf13/viper"
	jose "gopkg.in/square/go-jose.v2"
)

func TestAuthenticate(t *testing.T) {
	ctx := echo.New().AcquireContext()
	config := viper.New()

	t.Run(
		"Empty request",
		func(t *testing.T) {
			ca := OpenIDCAuth{}
			_, err := ca.Authenticate(ctx, *config)
			if err == nil {
				t.Fatalf("OIDC: check fail with empty request (%v)", err)
			}
		})
	t.Run(
		"Empty header",
		func(t *testing.T) {
			ca := OpenIDCAuth{}
			ctx.SetRequest(&http.Request{
				Header: http.Header{"Authz": []string{"error"}},
			})
			_, err := ca.Authenticate(ctx, *config)
			if err == nil {
				t.Fatalf("OIDC: check fail with authorization header not set (%v)", err)
			}
		})
	t.Run(
		"Not JWT header",
		func(t *testing.T) {
			ca := OpenIDCAuth{}
			ctx.SetRequest(&http.Request{
				Header: http.Header{"Authorization": []string{"bearer"}},
			})
			_, err := ca.Authenticate(ctx, *config)
			if err == nil {
				t.Fatalf("OIDC: check fail with authorization header not with 3 parts (%v)", err)
			}
		})
	t.Run(
		"JWT header mismatch (without dots)",
		func(t *testing.T) {
			ca := OpenIDCAuth{}
			ctx.SetRequest(&http.Request{
				Header: http.Header{"Authorization": []string{"JWT string_without_dots"}},
			})
			_, err := ca.Authenticate(ctx, *config)
			if err == nil {
				t.Fatalf("OIDC: check fail with mismatch JWT without dots (%v)", err)
			}
		})
	t.Run(
		"JWT header mismatch base64",
		func(t *testing.T) {
			ca := OpenIDCAuth{}
			ctx.SetRequest(&http.Request{
				Header: http.Header{"Authorization": []string{"JWT string.base64error().string"}},
			})
			_, err := ca.Authenticate(ctx, *config)
			if err == nil {
				t.Fatalf("OIDC: check fail with mismatch JWT not at base64 (%v)", err)
			}
		})
	t.Run(
		"JWT header mismatch base64",
		func(t *testing.T) {
			ca := OpenIDCAuth{}
			ctx.SetRequest(&http.Request{
				// not_an_json
				Header: http.Header{"Authorization": []string{"JWT string.bm90X2FuX2pzb24.string"}},
			})
			_, err := ca.Authenticate(ctx, *config)
			if err == nil {
				t.Fatalf("OIDC: check fail with mismatch JWT not at JSON (base64 encoded) (%v)", err)
			}
		})
	t.Run(
		"JWT header mismatch audience",
		func(t *testing.T) {
			ca := OpenIDCAuth{}
			ctx.SetRequest(&http.Request{
				// {"audience": ["mis_gsh"]}
				Header: http.Header{"Authorization": []string{"JWT string.eyJhdWRpZW5jZSI6IFsibWlzX2dzaCJdfQ.string"}},
			})
			_, err := ca.Authenticate(ctx, *config)
			if err == nil {
				t.Fatalf("OIDC: check fail with mismatch JWT audience (%v)", err)
			}
		})
	t.Run(
		"JWT header mismatch azp",
		func(t *testing.T) {
			ca := OpenIDCAuth{}
			ctx.SetRequest(&http.Request{
				// {"aud":["gsh"],"azp": "mis_gsh"}
				Header: http.Header{"Authorization": []string{"JWT string.eyJhdWQiOlsiZ3NoIl0sImF6cCI6ImdzaCIsImV4cCI6NTUxMTExMTExMX0.string"}},
			})
			config.Set("oidc_audience", "gsh")
			config.Set("oidc_authorized_party", "gsh")
			_, err := ca.Authenticate(ctx, *config)
			if err == nil {
				t.Fatalf("OIDC: check fail with mismatch JWT azp (%v)", err)
			}
		})
	t.Run(
		"JWT header mismatch expiration",
		func(t *testing.T) {
			ca := OpenIDCAuth{}
			ctx.SetRequest(&http.Request{
				// {"aud": ["gsh"],"azp":"gsh","exp":1111111111} # 17/03/2005
				Header: http.Header{"Authorization": []string{"JWT string.eyJleHAiOjExMTExMTExMTEsImF1ZCI6WyJnc2giXSwiYXpwIjoiZ3NoIn0.string"}},
			})
			config.Set("oidc_audience", "gsh")
			config.Set("oidc_authorized_party", "gsh")
			_, err := ca.Authenticate(ctx, *config)
			if err == nil {
				t.Fatalf("OIDC: check fail with invalid JWT expiration (%v)", err)
			}
		})
	t.Run(
		"JWT header mismatch signature",
		func(t *testing.T) {
			ca := OpenIDCAuth{}
			ctx.SetRequest(&http.Request{
				// {"exp": 9999999999,"aud": ["gsh"],"azp": "gsh"}
				Header: http.Header{"Authorization": []string{"JWT string.eyJleHAiOjk5OTk5OTk5OTk5LCJhdWQiOlsiZ3NoIl0sImF6cCI6ImdzaCJ9.string"}},
			})
			config.Set("oidc_audience", "gsh")
			config.Set("oidc_authorized_party", "gsh")
			jws := `{
				"keys": [
				  {
					"kty": "RSA",
					"d": "m9S3A5YNrU_gwOx_8GHkwwh7k6FL2kunnitJ5HPMJ_pYAN_x9W2L5Cm7Cb0QE1x6SeaNSNYvq2_fb1F1l7NhqJqodPKipA-fhihSPWwEMef_wae0YYrVx_1hHALH9MjrVHf9F-rYN77Goc2I52y0p0vlSegyEO-vwDB5p0vJrECrUCVFOHleV3g62WCK_wefoUUIzbV_0eLSLu0U3e7QgKqk8_Ho__B1QHG5Fk1poKxI2zPf8Tz2xSCK-qQi1yXKtRoW216CI-8MX-8ub1Q7XYkFepUMDdlBn_p3sxIUFAF_J9vC9kpnnzY3TeiWK6NWzU0b3IH_SbxdNqGCWeT_8Q",
					"e": "AQAB",
					"use": "sig",
					"kid": "gsh",
					"alg": "RS256",
					"n": "2fH0CYidOjU718EGZCwa7X31Fcwmw75i8s-zQGdpJiFhSjIGjWrqocCW-mEA51vJCAewDyQetkhWZsocS3aIEPs5ujrhTlwvCXS5MKl_xHPDaUdBtnM8rF7IFLGpu9XCWZTw1tAHRO9B4kUq_sH6C41dCusJna7U4Ng4uoV-OjmUYpde7YQiMm-iNqeKalj6sXxsiVJwcjpZthoH0PW8yf4Ccmr5FXfRD94vAkeW9oCvvhYxVJHzU9fHVU0giyYq34qQiJsscASBdoJ7AuAiPYwaWt0nY3XL8BmUN0OZybk3HTQXyk5XNtvEwNL3ZleK1EQOZCFj1h_UdZsvrVCWRw"
				  }
				]
			}`
			var keySet jose.JSONWebKeySet
			json.Unmarshal([]byte(jws), &keySet)
			config.Set("oidc_keys", keySet)
			_, err := ca.Authenticate(ctx, *config)
			if err == nil {
				t.Fatalf("OIDC: check fail with malformed JWT signature (%v)", err)
			}
		})
}

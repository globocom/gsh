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
		"JWT header mismatch audience (as string)",
		func(t *testing.T) {
			ca := OpenIDCAuth{}
			ctx.SetRequest(&http.Request{
				// {"audience": "mis_gsh"}
				Header: http.Header{"Authorization": []string{"JWT string.eyJhdWQiOiJnc2gifQ.string"}},
			})
			_, err := ca.Authenticate(ctx, *config)
			if err == nil {
				t.Fatalf("OIDC: check fail with mismatch JWT audience string (%v)", err)
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
	t.Run(
		"JWT header match signature, but issuer not recognized",
		func(t *testing.T) {
			ca := OpenIDCAuth{}
			ctx.SetRequest(&http.Request{
				// {"exp": 9999999999,"aud": ["gsh"],"azp": "gsh"}
				Header: http.Header{"Authorization": []string{"JWT eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXVCJ9.eyJleHAiOjk5OTk5OTk5OTk5LCJhdWQiOlsiZ3NoIl0sImF6cCI6ImdzaCJ9.OLLARTd2sZFzhOvuKnKYZO3FZXC9xQakmmxag6MW9ZXmy3--wAHF4vOTDcCAQ7yx6yP8KPrZ2xqMhSqBCbKxhAXTtrEE5J4zaZqE4mYW8eL8ShoW3ltkeF1VaUBGeRJROpwf4q8Aax32FbQCF7rMFFT6KIJi5v6HK-NsKT1o-wxaNmxpcvnafoFJv4Fo2VEH2NbDwOJujAJteeYrbnEeKm3MoK5mWSbp6XWbetFf__2Raju58n-vy-c8MbgwOf61V7c14m6yWuA4oFCr6K4ENHyqF0rZ-L6WdzHwHQUpTFl9k8-WWir4TYgxr2SM90_EhwlcjioMOgaOClBYg8CW8g"}},
			})
			config.Set("oidc_audience", "gsh")
			config.Set("oidc_authorized_party", "gsh")
			jws := `{
					"keys": [
						{
							"kty": "RSA",
							"e": "AQAB",
							"n": "2fH0CYidOjU718EGZCwa7X31Fcwmw75i8s-zQGdpJiFhSjIGjWrqocCW-mEA51vJCAewDyQetkhWZsocS3aIEPs5ujrhTlwvCXS5MKl_xHPDaUdBtnM8rF7IFLGpu9XCWZTw1tAHRO9B4kUq_sH6C41dCusJna7U4Ng4uoV-OjmUYpde7YQiMm-iNqeKalj6sXxsiVJwcjpZthoH0PW8yf4Ccmr5FXfRD94vAkeW9oCvvhYxVJHzU9fHVU0giyYq34qQiJsscASBdoJ7AuAiPYwaWt0nY3XL8BmUN0OZybk3HTQXyk5XNtvEwNL3ZleK1EQOZCFj1h_UdZsvrVCWRw"
						}
					]
				}`
			var keySet jose.JSONWebKeySet
			json.Unmarshal([]byte(jws), &keySet)
			config.Set("oidc_keys", keySet)

			_, err := ca.Authenticate(ctx, *config)
			if err == nil {
				t.Fatalf("OIDC: check fail with well-formed JWT signature without issuer (%v)", err)
			}
		})
	t.Run(
		"JWT without user field configured",
		func(t *testing.T) {
			ca := OpenIDCAuth{}
			ctx.SetRequest(&http.Request{
				// {"exp":99999999999,"aud":["gsh"],"azp":"gsh","iss":"accounts.example.org/gsh"}
				Header: http.Header{"Authorization": []string{"JWT eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXVCJ9.eyJleHAiOjk5OTk5OTk5OTk5LCJhdWQiOlsiZ3NoIl0sImF6cCI6ImdzaCIsImlzcyI6ImFjY291bnRzLmV4YW1wbGUub3JnL2dzaCJ9.KCTO-fLzQWGKdVeoSkmZctzVPQZDmXlCFOgQBDL5_dIIlshce_sZ6lyGR5gmafaTVHqdUiC27BxBqYvOgmma1FpUiohQfFDrD9RwZyPtT-jHCkDp-edq5Ot_WngFgNvf_PPttaJlBlRn5kUayU9h57iPNz8DFbNiJrSULauKk8GtVqRZabexnfm91HHdMsMdZ4IMK4_OOFfqULknZTzzVNc0EO63IARyeK9kGhaj3d3ha2wed5GvCRDgTT9Xo29ekF3a3XlIyvz5lCdtW1EvjmG7oXzuTUlzyBuxKRrUqtZ8zVaMOHDNO23PobsEeDtybC4-sBANZCNfsVl8WNxJXg"}},
			})
			config.Set("oidc_audience", "gsh")
			config.Set("oidc_authorized_party", "gsh")
			jws := `{
					"keys": [
						{
							"kty": "RSA",
							"e": "AQAB",
							"n": "2fH0CYidOjU718EGZCwa7X31Fcwmw75i8s-zQGdpJiFhSjIGjWrqocCW-mEA51vJCAewDyQetkhWZsocS3aIEPs5ujrhTlwvCXS5MKl_xHPDaUdBtnM8rF7IFLGpu9XCWZTw1tAHRO9B4kUq_sH6C41dCusJna7U4Ng4uoV-OjmUYpde7YQiMm-iNqeKalj6sXxsiVJwcjpZthoH0PW8yf4Ccmr5FXfRD94vAkeW9oCvvhYxVJHzU9fHVU0giyYq34qQiJsscASBdoJ7AuAiPYwaWt0nY3XL8BmUN0OZybk3HTQXyk5XNtvEwNL3ZleK1EQOZCFj1h_UdZsvrVCWRw"
						}
					]
				}`
			var keySet jose.JSONWebKeySet
			json.Unmarshal([]byte(jws), &keySet)
			config.Set("oidc_keys", keySet)
			// make issuer ok
			config.Set("oidc_base_url", "accounts.example.org")
			config.Set("oidc_realm", "gsh")

			_, err := ca.Authenticate(ctx, *config)
			if err == nil {
				t.Fatalf("OIDC: check fail, JWT without claim field (%v)", err)
			}
		})
	t.Run(
		"JWT with user field",
		func(t *testing.T) {
			ca := OpenIDCAuth{}
			ctx.SetRequest(&http.Request{
				// {"exp":99999999999,"aud":["gsh"],"azp":"gsh","iss":"accounts.example.org/gsh","email":"gsh@accounts.example.org"}
				Header: http.Header{"Authorization": []string{"JWT eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXVCJ9.eyJleHAiOjk5OTk5OTk5OTk5LCJhdWQiOlsiZ3NoIl0sImF6cCI6ImdzaCIsImlzcyI6ImFjY291bnRzLmV4YW1wbGUub3JnL2dzaCIsImVtYWlsIjoiZ3NoQGFjY291bnRzLmV4YW1wbGUub3JnIn0.fJYfGGwgf9rFtpbNwIXAVx38VVgh7ByLhfPVM-WztbcTVVwukSMrPBznbL0RFOLwSgxyzi6SCRP1CjygMHphEjT1ekZrKyPdX9ay6iaSNA-HAeD2FeUey1G-uD6rpV3X9vhBQNtfWjZcTUoKsdksHxbkSu_3URjVW9UFUwf0ErRk7-JirFyKVUKMOMeXtepgVU94H9V1Id0YXBCaGc26gQtoe9O8oY78LBIWQ1SEy8seUEA9CBwkgkXjkAYKpKh1mcf84jtvRw4l6usIeZwQKuu6UIflgeyk0HAMNdW9HfCFYfyiSwK32XXL-X7uJzMd7Nt5EX4lUa5jf_isd-HN7A"}},
			})
			config.Set("oidc_audience", "gsh")
			config.Set("oidc_authorized_party", "gsh")
			jws := `{
						"keys": [
							{
								"kty": "RSA",
								"e": "AQAB",
								"n": "2fH0CYidOjU718EGZCwa7X31Fcwmw75i8s-zQGdpJiFhSjIGjWrqocCW-mEA51vJCAewDyQetkhWZsocS3aIEPs5ujrhTlwvCXS5MKl_xHPDaUdBtnM8rF7IFLGpu9XCWZTw1tAHRO9B4kUq_sH6C41dCusJna7U4Ng4uoV-OjmUYpde7YQiMm-iNqeKalj6sXxsiVJwcjpZthoH0PW8yf4Ccmr5FXfRD94vAkeW9oCvvhYxVJHzU9fHVU0giyYq34qQiJsscASBdoJ7AuAiPYwaWt0nY3XL8BmUN0OZybk3HTQXyk5XNtvEwNL3ZleK1EQOZCFj1h_UdZsvrVCWRw"
							}
						]
					}`
			var keySet jose.JSONWebKeySet
			json.Unmarshal([]byte(jws), &keySet)
			config.Set("oidc_keys", keySet)
			// make issuer ok
			config.Set("oidc_base_url", "accounts.example.org")
			config.Set("oidc_realm", "gsh")
			config.Set("oidc_claim", "Email")
			config.Set("oidc_claim_name", "email")

			_, err := ca.Authenticate(ctx, *config)
			if err != nil {
				t.Fatalf("OIDC: check fail with JWT and issuer OK (%v)", err)
			}

			// check for JTI at session
			jti := ctx.Get("JTI")
			if jti != "" {
				t.Fatalf("OIDC: invalid JTI at JWT without JTI (%v)", jti)
			}

		})
	t.Run(
		"Check for JTI after JWT validation",
		func(t *testing.T) {
			ca := OpenIDCAuth{}
			ctx.SetRequest(&http.Request{
				// {"exp":99999999999,"aud":["gsh"],"azp":"gsh","iss":"accounts.example.org/gsh","email":"gsh@accounts.example.org","jti":"jti-value"}
				Header: http.Header{"Authorization": []string{"JWT eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXVCJ9.eyJleHAiOjk5OTk5OTk5OTk5LCJhdWQiOlsiZ3NoIl0sImF6cCI6ImdzaCIsImlzcyI6ImFjY291bnRzLmV4YW1wbGUub3JnL2dzaCIsImVtYWlsIjoiZ3NoQGFjY291bnRzLmV4YW1wbGUub3JnIiwianRpIjoianRpLXZhbHVlIn0.qgR5_l1dgw32w9F9UCoWdCAc64ykHz4EDWT9U-CX25fTvSuSsmO_jvglfABQZXBHi1PdwQCdJWQ0bQ1STDADyEjIQJEZwgF7gTWf7KDUO0dDibWM3Ac9PHIlhrEYJ-N2bDyNxz0FVQY3pjD3g-w2Qy_AWFhmuX4d3ElgIq6qmqPnK91fwXcojxaeEwiNT5H5RoEYWCbaOmiDexA-xmwuHpEqPul3O0k0WFqYff1SOCxmDh-e4qgM60VB3GUC2AW06B8IQLF3sYamHf1i01D9I48E5Jgd9c533Bz0uyWtC0XqCukoRn0iQEjLPcoCLvV9xkLl1NX7rlYbATU4ocfM_A"}},
			})
			config.Set("oidc_audience", "gsh")
			config.Set("oidc_authorized_party", "gsh")
			jws := `{
							"keys": [
								{
									"kty": "RSA",
									"e": "AQAB",
									"n": "2fH0CYidOjU718EGZCwa7X31Fcwmw75i8s-zQGdpJiFhSjIGjWrqocCW-mEA51vJCAewDyQetkhWZsocS3aIEPs5ujrhTlwvCXS5MKl_xHPDaUdBtnM8rF7IFLGpu9XCWZTw1tAHRO9B4kUq_sH6C41dCusJna7U4Ng4uoV-OjmUYpde7YQiMm-iNqeKalj6sXxsiVJwcjpZthoH0PW8yf4Ccmr5FXfRD94vAkeW9oCvvhYxVJHzU9fHVU0giyYq34qQiJsscASBdoJ7AuAiPYwaWt0nY3XL8BmUN0OZybk3HTQXyk5XNtvEwNL3ZleK1EQOZCFj1h_UdZsvrVCWRw"
								}
							]
						}`
			var keySet jose.JSONWebKeySet
			json.Unmarshal([]byte(jws), &keySet)
			config.Set("oidc_keys", keySet)
			// make issuer ok
			config.Set("oidc_base_url", "accounts.example.org")
			config.Set("oidc_realm", "gsh")
			config.Set("oidc_claim", "Email")
			config.Set("oidc_claim_name", "email")

			_, err := ca.Authenticate(ctx, *config)
			if err != nil {
				t.Fatalf("OIDC: check fail with JWT valid (%v)", err)
			}

			// check for JTI at session
			jti := ctx.Get("JTI")
			if jti != "jti-value" {
				t.Fatalf("OIDC: invalid JTI at JWT with JTI (%v)", jti)
			}
		})
}

package config

import (
	"os"
	"testing"

	"github.com/spf13/viper"
)

func TestInit(t *testing.T) {
	result := Init()
	if !result.IsSet("storage_uri") {
		t.Fatal("Config: storage_uri not set automatically")
	}
	if os.Getenv("PORT") == "" {
		t.Fatal("Config: PORT not set automatically")
	}
}

func TestCheck(t *testing.T) {
	// Test if PORT is set
	t.Run(
		"PORT",
		func(t *testing.T) {
			os.Unsetenv("PORT")
			result := viper.New()
			err := Check(*result)
			if err == nil {
				t.Fatal("Config: PORT must be automatically configured")
			}
		})

	// Test external CA
	t.Run(
		"GSH_EXTERNAL_CA",
		func(t *testing.T) {
			result := Init()
			os.Setenv("GSH_CA_EXTERNAL", "1")
			err := Check(result)
			if err == nil {
				t.Fatal("Config: check fail using external CA")
			}
		})

	// Test internal CA
	t.Run(
		"GSH_EXTERNAL_CA",
		func(t *testing.T) {
			result := Init()
			os.Setenv("GSH_CA_EXTERNAL", "0")
			err := Check(result)
			if err == nil {
				t.Fatal("Config: check fail using external CA")
			}
		})

	// Test external CA + OIDC
	t.Run(
		"GSH_EXTERNAL_CA",
		func(t *testing.T) {
			result := Init()
			os.Setenv("GSH_CA_EXTERNAL", "1")
			err := Check(result)
			if err == nil {
				t.Fatal("Config: check fail using external CA")
			}
		})

	// Test internal CA
	t.Run(
		"GSH_EXTERNAL_CA",
		func(t *testing.T) {
			result := Init()
			os.Setenv("GSH_CA_EXTERNAL", "0")
			err := Check(result)
			if err == nil {
				t.Fatal("Config: check fail using external CA")
			}
		})

}

func TestCheckCAExternal(t *testing.T) {
	result := Init()

	os.Setenv("GSH_CA_EXTERNAL", "1")
	os.Setenv("GSH_CA_SIGNER_URL", "https://vault.example.org/signer")
	os.Setenv("GSH_CA_PUBLIC_KEY_URL", "https://vault.example.org/publickey")
	os.Setenv("GSH_CA_ENDPOINT", "https://vault.example.org/ca")
	os.Setenv("GSH_CA_ROLE_ID", "gsh")
	os.Setenv("GSH_CA_EXTERNAL_SECRET_ID", "secret")

	os.Setenv("GSH_OIDC_BASE_URL", "https://openid.example.org/realm")
	os.Setenv("GSH_OIDC_REALM", "gsh")
	os.Setenv("GSH_OIDC_AUDIENCE", "gsh")
	os.Setenv("GSH_OIDC_CLAIM", "email")

	err := Check(result)
	if err != nil {
		t.Fatal("Config: check fail using external CA")
	}

}

func TestCheckCAInternal(t *testing.T) {
	result := Init()

	os.Setenv("GSH_CA_EXTERNAL", "0")
	os.Setenv("GSH_CA_PRIVATE_KEY", `-----BEGIN OPENSSH PRIVATE KEY-----
	b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABFwAAAAdzc2gtcn
	NhAAAAAwEAAQAAAQEA24NYmz8YFN1gWFwbIjbiDk1bkQ3ehgeMX+/9Z87tOSNlRDQjlSEw
	Z/Da2XI8jpqrkeheMLafg8tCoB99MqXNs7opjYY3CUjzTFHHTm0ahcJFOwZehuuzZfPquI
	ga3L6FVU9u58fdsB/6PLq/jkLtYDV3JFi/0VTqo6Coihci0DOptYG8RElO1w/GTpaXexvr
	VwOmcTyjJv/8mXZ0sPDHRR5qGR0MS5I50NJipxJYD1AstjQADMOXX/5wiuemluNLXg2M0B
	jZppkB3dsPdF6YIPSr9j51po/7pDtypSchy09YMAey9/c6iqtN2hEOlo32f12mALWza1S4
	wAWb0AR9IQAAA9j/wNeT/8DXkwAAAAdzc2gtcnNhAAABAQDbg1ibPxgU3WBYXBsiNuIOTV
	uRDd6GB4xf7/1nzu05I2VENCOVITBn8NrZcjyOmquR6F4wtp+Dy0KgH30ypc2zuimNhjcJ
	SPNMUcdObRqFwkU7Bl6G67Nl8+q4iBrcvoVVT27nx92wH/o8ur+OQu1gNXckWL/RVOqjoK
	iKFyLQM6m1gbxESU7XD8ZOlpd7G+tXA6ZxPKMm//yZdnSw8MdFHmoZHQxLkjnQ0mKnElgP
	UCy2NAAMw5df/nCK56aW40teDYzQGNmmmQHd2w90Xpgg9Kv2PnWmj/ukO3KlJyHLT1gwB7
	L39zqKq03aEQ6WjfZ/XaYAtbNrVLjABZvQBH0hAAAAAwEAAQAAAQAhDkVwk26/7ZpNlAkt
	/M/L0ZBhZpJE4qwb4lrpn/qPKSpdu/BDy8yrSlTae95spxQBE9njQg0BXsF4tWU4FEnGr9
	kEC9sL1eV1b7cwszNUQy4DtnDTpnjMeI+3HB/XcAVKFH0iADH9DMO1E3Y3KRLv8v0vBwJT
	tpLi8xWOPe+rJGTn96vH5Cu/8dgYjEVLtQmxnJop+Bs4Oe2GxA9s9TDn2mX53QuEhnWdSx
	26B6ttbPeVYX6kkDbip9K++I0+CoBA90ZlKN1rtzzxRI4XyDOUJkaQ94jNhbodA8f8/Bo/
	o5XfD+b+jH/+C7saqAwhm1xN5kyt6okS6SXmV8B+XH+1AAAAgCJWiJnlxzOmU+sqnUtyfA
	EjT/KZ4I7XIB1NMI9NaU2bKJblmS4rXssOCoGvh+WhQbrX6Z0qsqRrRk2WdMokTuZz0E8H
	bdpUzVeB9hvQQSBKtD/Dq35xnFT6eeO2yHeBeR5FJTS2zyfK819RoGeEyBHqSlvUSYsOf8
	KJrXxDRvWDAAAAgQD/kYZEt3Fvgjdc+xwB2vydAppE7aq4GOs1Mwa9bYBLnnchDi3BDYGw
	zPBr9FfeZMgG7xk+ikurhLk2Io8iuYs9crl2KhtKa5C/fkOOOlC5WSV4i/K/UlogkOhTi4
	vWzMGK48Ls7GklFhTXQnd/DYIfdU63EJZ3yV9+vI1lsnR/NwAAAIEA2+I8X/tzrRvkXl6L
	rtBIq2kuh4A+ILCdv13jELQUemD4oxKwsPatx1rdqDn344zLaMVxPRXctjdj54+prNwu7p
	+snJcexfl3G+Q8L/LXfbRiXWEpjjLWiVHk7ditSgPtgbFIva5J377wPK86IjU/dmggWZIp
	lUuFTR5TiWfAImcAAAAdbWFub2VsLmp1bmlvckBtYWMzMDExODgubG9jYWwBAgMEBQY=
	-----END OPENSSH PRIVATE KEY-----`)
	os.Setenv("GSH_CA_PUBLIC_KEY", "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDbg1ibPxgU3WBYXBsiNuIOTVuRDd6GB4xf7/1nzu05I2VENCOVITBn8NrZcjyOmquR6F4wtp+Dy0KgH30ypc2zuimNhjcJSPNMUcdObRqFwkU7Bl6G67Nl8+q4iBrcvoVVT27nx92wH/o8ur+OQu1gNXckWL/RVOqjoKiKFyLQM6m1gbxESU7XD8ZOlpd7G+tXA6ZxPKMm//yZdnSw8MdFHmoZHQxLkjnQ0mKnElgPUCy2NAAMw5df/nCK56aW40teDYzQGNmmmQHd2w90Xpgg9Kv2PnWmj/ukO3KlJyHLT1gwB7L39zqKq03aEQ6WjfZ/XaYAtbNrVLjABZvQBH0h alice@example.org")

	os.Setenv("GSH_OIDC_BASE_URL", "https://openid.example.org/realm")
	os.Setenv("GSH_OIDC_REALM", "gsh")
	os.Setenv("GSH_OIDC_AUDIENCE", "gsh")
	os.Setenv("GSH_OIDC_CLAIM", "email")

	err := Check(result)
	if err != nil {
		t.Fatal("Config: check fail using external CA")
	}

}

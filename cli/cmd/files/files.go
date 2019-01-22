// Copyright © 2019 Globo.com
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice,
//    this list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its contributors
//    may be used to endorse or promote products derived from this software
//    without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
// ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
// LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
// CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
// SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
// CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.

package files

import (
	"io/ioutil"
	"os"

	"github.com/globocom/gsh/cli/cmd/config"
	"github.com/globocom/gsh/types"
	"github.com/labstack/gommon/random"
	homedir "github.com/mitchellh/go-homedir"
)

// GetConfigPath return Viper config path
func GetConfigPath() (string, error) {
	// Find home directory.
	home, err := homedir.Dir()
	if err != nil {
		return "", err
	}

	// check if .gshc folder exists and creates if it not exists
	path := home + "/.gshc"
	if _, err := os.Stat(path); os.IsNotExist(err) {
		err := os.Mkdir(path, 0750)
		if err != nil {
			return "", err
		}
	}
	return path, nil
}

// WriteKeys saves string as files and returns the files paths
func WriteKeys(key string, cert string) (string, string, error) {
	// Find home directory.
	configPath, err := GetConfigPath()
	if err != nil {
		return "", "", err
	}

	// Set specific path for certificates and private keys
	certPath := configPath + "/certs"
	if _, err := os.Stat(certPath); os.IsNotExist(err) {
		err := os.Mkdir(certPath, 0750)
		if err != nil {
			return "", "", err
		}
	}

	// Set specific per target
	// Get current target
	currentTarget := new(types.Target)
	currentTarget = config.GetCurrentTarget()
	path := certPath + "/" + currentTarget.Label
	if _, err := os.Stat(path); os.IsNotExist(err) {
		err := os.Mkdir(path, 0750)
		if err != nil {
			return "", "", err
		}
	}

	// Store private key file with random name
	id := random.String(32)
	keyFileLocation := path + "/" + id
	keyFile, err := os.Create(keyFileLocation)
	defer keyFile.Close()
	if err != nil {
		return "", "", err
	}
	ioutil.WriteFile(keyFileLocation, []byte(key), 0600)
	os.Chmod(keyFileLocation, 0600)

	// Store cert file with suffix "-cert.pub" (https://man.openbsd.org/ssh.1#i)
	certLocation := path + "/" + id + "-cert.pub"
	certFile, err := os.Create(certLocation)
	defer certFile.Close()
	if err != nil {
		return "", "", err
	}
	ioutil.WriteFile(certLocation, []byte(cert), 0650)

	return keyFileLocation, certLocation, nil
}

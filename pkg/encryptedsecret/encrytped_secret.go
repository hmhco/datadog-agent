// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2018 Datadog, Inc.

// +build !windows

package encryptedsecret

import (
	"fmt"
	"strings"

	log "github.com/cihub/seelog"
	yaml "gopkg.in/yaml.v2"

	"github.com/DataDog/datadog-agent/pkg/config"
)

var secretCache map[string]string

func init() {
	secretCache = make(map[string]string)
}

type walkerCallback func(string) (string, error)

func walkSlice(data []interface{}, callback walkerCallback) error {
	for idx, k := range data {
		if v, ok := k.(string); ok {
			newValue, err := callback(v)
			if err != nil {
				return err
			}
			data[idx] = newValue
		}
		if v, ok := k.(map[interface{}]interface{}); ok {
			if err := walkHash(v, callback); err != nil {
				return err
			}
		}
		if v, ok := k.([]interface{}); ok {
			if err := walkSlice(v, callback); err != nil {
				return err
			}
		}
	}
	return nil
}

func walkHash(data map[interface{}]interface{}, callback walkerCallback) error {
	for k := range data {
		if v, ok := data[k].(string); ok {
			newValue, err := callback(v)
			if err != nil {
				return err
			}
			data[k] = newValue
		}
		if v, ok := data[k].(map[interface{}]interface{}); ok {
			if err := walkHash(v, callback); err != nil {
				return err
			}
		}
		if v, ok := data[k].([]interface{}); ok {
			if err := walkSlice(v, callback); err != nil {
				return err
			}
		}
	}
	return nil
}

// walk will go through loaded yaml and call callback on every strings allowing
// the callback to overwrite the string value
func walk(data *interface{}, callback walkerCallback) error {
	if v, ok := (*data).(string); ok {
		newValue, err := callback(v)
		if err != nil {
			return err
		}
		*data = newValue
	}
	if v, ok := (*data).(map[interface{}]interface{}); ok {
		return walkHash(v, callback)
	}
	if v, ok := (*data).([]interface{}); ok {
		return walkSlice(v, callback)
	}
	return nil
}

func isEnc(str string) (bool, string) {
	str = strings.Trim(str, " 	")
	if strings.HasPrefix(str, "ENC[") && strings.HasSuffix(str, "]") {
		return true, str[4 : len(str)-1]
	}
	return false, ""
}

// testing purpose
var secretFetcher = fetchSecret

// Decrypt replaces all encrypted passwords in data by executing
// "secret_backend_command" once if all secrets aren't present in the cache.
func Decrypt(data []byte) ([]byte, error) {
	if data == nil || config.Datadog.GetString("secret_backend_command") == "" {
		return data, nil
	}

	var config interface{}
	err := yaml.Unmarshal(data, &config)
	if err != nil {
		return nil, fmt.Errorf("Could not Unmarshal config: %s", err)
	}

	// First we collect all passwords in the config
	handles := []string{}
	haveSecret := false
	err = walk(&config, func(str string) (string, error) {
		if ok, handle := isEnc(str); ok {
			haveSecret = true
			// Check if we already know this secret
			if secret, ok := secretCache[handle]; ok {
				log.Debugf("Secret '%s' was retrieved from cache", handle)
				return secret, nil
			}
			handles = append(handles, handle)
		}
		return str, nil
	})
	if err != nil {
		return nil, err
	}

	// the configuration does not contain any passwords
	if !haveSecret {
		return data, nil
	}

	// check if any new passwords need to be fetch
	if len(handles) != 0 {
		passwords, err := secretFetcher(handles)
		if err != nil {
			return nil, err
		}

		// Replace all new encrypted passwords in the config
		err = walk(&config, func(str string) (string, error) {
			if ok, handle := isEnc(str); ok {
				if secret, ok := passwords[handle]; ok {
					log.Debugf("Secret '%s' was retrieved from executable", handle)
					return secret, nil
				}
				// This should never happen since fetchSecret will return an error
				// if not every handles have been fetched.
				return str, fmt.Errorf("Unknown secret '%s'", handle)
			}
			return str, nil
		})
		if err != nil {
			return nil, err
		}
	}

	finalConfig, err := yaml.Marshal(config)
	if err != nil {
		return nil, fmt.Errorf("Could not Marshal config after replace encrypted secrets: %s", err)
	}
	return finalConfig, nil
}

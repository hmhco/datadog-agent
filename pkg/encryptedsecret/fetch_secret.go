// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2018 Datadog, Inc.

// +build !windows

package encryptedsecret

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/DataDog/datadog-agent/pkg/config"
)

const payloadVersion = "1.0"

type limitBuffer struct {
	cap int
	buf *bytes.Buffer
}

func (b *limitBuffer) Write(p []byte) (n int, err error) {
	if len(p)+b.buf.Len() > b.cap {
		return 0, fmt.Errorf("command output was too long: exceeded %d byte", b.cap)
	}
	return b.buf.Write(p)
}

func execCommand(inputPayload string) ([]byte, error) {
	command := config.Datadog.GetString("secret_backend_command")
	args := config.Datadog.GetStringSlice("secret_backend_arguments")

	if command == "" {
		return nil, fmt.Errorf("No secret_backend_command set: could not decrpyt secret")
	}

	ctx, cancel := context.WithTimeout(context.Background(),
		time.Duration(config.Datadog.GetInt("secret_backend_timeout"))*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, command, args...)
	if err := checkRights(cmd.Path); err != nil {
		return nil, err
	}

	cmd.Stdin = strings.NewReader(inputPayload)
	// setting an empty env in case some secrets where set using the ENV (ex: API_KEY)
	cmd.Env = []string{}

	out := limitBuffer{
		buf: &bytes.Buffer{},
		cap: config.Datadog.GetInt("secret_backend_output_max_size"),
	}
	cmd.Stdout = &out

	err := cmd.Run()
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return nil, fmt.Errorf("Error while running '%s': command timeout", command)
		}
		return nil, fmt.Errorf("Error while running '%s': %s", command, err)
	}
	return out.buf.Bytes(), nil
}

type secret struct {
	Value    string
	ErrorMsg string `json:"error"`
}

// for testing purpose
var runCommand = execCommand

func fetchSecret(secrets []string) (map[string]string, error) {
	payload := map[string]interface{}{
		"version": payloadVersion,
		"secrets": secrets,
	}
	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("Could not serialize secrets to fetch password: %s", err)
	}
	output, err := runCommand(string(jsonPayload))
	if err != nil {
		return nil, err
	}

	passwords := map[string]secret{}
	err = json.Unmarshal(output, &passwords)
	if err != nil {
		return nil, fmt.Errorf("Could not unmarshal 'secret_backend_command' output: %s", err)
	}

	res := map[string]string{}
	for _, sec := range secrets {
		v, ok := passwords[sec]
		if ok == false {
			return nil, fmt.Errorf("secret handle '%s' was not decrpyted by the secret_backend_command", sec)
		}

		if v.ErrorMsg != "" {
			return nil, fmt.Errorf("An error occurs while decrpyting '%s': %s", sec, v.ErrorMsg)
		}
		if v.Value == "" {
			return nil, fmt.Errorf("error: decrpyted password for '%s' is empty", sec)
		}
		// add it to the cache
		secretCache[sec] = v.Value
		res[sec] = v.Value
	}
	return res, nil
}

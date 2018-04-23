// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2018 Datadog, Inc.

package common

// SetupConfigOSSpecifics any additional OS-specific configuration necessary
// should be called _after_ SetupConfig()
func SetupConfigOSSpecifics() error {
	return nil
}

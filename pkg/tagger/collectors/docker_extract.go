// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2018 Datadog, Inc.

// +build docker

package collectors

import (
	"fmt"
	"strings"

	log "github.com/cihub/seelog"
	"github.com/docker/docker/api/types"

	"github.com/DataDog/datadog-agent/pkg/tagger/utils"
	"github.com/DataDog/datadog-agent/pkg/util/docker"
)

// extractFromInspect extract tags for a container inspect JSON
func (c *DockerCollector) extractFromInspect(co types.ContainerJSON) ([]string, []string, error) {
	tags := utils.NewTagList()

	//TODO: remove when Inspect returns resolved image names
	dockerImage, err := c.dockerUtil.ResolveImageName(co.Image)
	if err != nil {
		log.Debugf("Error resolving image %s: %s", co.Image, err)
	} else {
		dockerExtractImage(tags, dockerImage)
	}
	dockerExtractLabels(tags, co.Config.Labels, c.labelsAsTags)
	dockerExtractEnvironmentVariables(tags, co.Config.Env, c.envAsTags)

	tags.AddHigh("container_name", strings.TrimPrefix(co.Name, "/"))
	tags.AddHigh("container_id", co.ID)

	low, high := tags.Compute()
	return low, high, nil
}

func dockerExtractImage(tags *utils.TagList, dockerImage string) {
	tags.AddLow("docker_image", dockerImage)
	imageName, shortImage, imageTag, err := docker.SplitImageName(dockerImage)
	if err != nil {
		log.Debugf("Cannot split %s: %s", dockerImage, err)
		return
	}
	tags.AddLow("image_name", imageName)
	tags.AddLow("short_image", shortImage)
	tags.AddLow("image_tag", imageTag)
}

// dockerExtractLabels contain hard-coded labels from:
// - Docker swarm
func dockerExtractLabels(tags *utils.TagList, containerLabels map[string]string, labelsAsTags map[string]string) {

	for labelName, labelValue := range containerLabels {
		switch labelName {
		// Docker swarm
		case "com.docker.swarm.service.name":
			tags.AddLow("swarm_service", labelValue)
		case "com.docker.stack.namespace":
			tags.AddLow("swarm_namespace", labelValue)

		// Rancher 1.x
		case "io.rancher.container.name":
			tags.AddHigh("rancher_container", labelValue)
		case "io.rancher.stack.name":
			tags.AddLow("rancher_stack", labelValue)
		case "io.rancher.stack_service.name":
			tags.AddLow("rancher_service", labelValue)

		default:
			if tagName, found := labelsAsTags[strings.ToLower(labelName)]; found {
				tags.AddAuto(tagName, labelValue)
			}
		}
	}
}

// dockerExtractEnvironmentVariables contain hard-coded environment variables from:
// - Mesos/DCOS tags (mesos, marathon, chronos)
func dockerExtractEnvironmentVariables(tags *utils.TagList, containerEnvVariables []string, envAsTags map[string]string) {
	var envSplit []string
	var envName, envValue string

	for _, envEntry := range containerEnvVariables {
		envSplit = strings.SplitN(envEntry, "=", 2)
		if len(envSplit) != 2 {
			continue
		}
		envName = envSplit[0]
		envValue = envSplit[1]
		switch envName {
		// Mesos/DCOS tags (mesos, marathon, chronos)
		case "MARATHON_APP_ID":
			tags.AddLow("marathon_app", envValue)
		case "CHRONOS_JOB_NAME":
			tags.AddLow("chronos_job", envValue)
		case "CHRONOS_JOB_OWNER":
			tags.AddLow("chronos_job_owner", envValue)
		case "MESOS_TASK_ID":
			tags.AddHigh("mesos_task", envValue)

		// Apache Aurora Scheduler
		case "MESOS_EXECUTOR_ID":
			for k, v := range dockerExtractAuroraTagsFromExecId(envValue) {
				tags.AddLow(fmt.Sprintf("aurora.docker.%s", k), v)
			}

		// Nomad
		case "NOMAD_TASK_NAME":
			tags.AddLow("nomad_task", envValue)
		case "NOMAD_JOB_NAME":
			tags.AddLow("nomad_job", envValue)
		case "NOMAD_GROUP_NAME":
			tags.AddLow("nomad_group", envValue)

		default:
			if tagName, found := envAsTags[strings.ToLower(envSplit[0])]; found {
				tags.AddAuto(tagName, envValue)
			}
		}
	}
}

// dockerExtractAuroraTagsFromExecId contain parsed Apache Aurora Scheduler tags from:
// Mesos set MESOS_EXECUTOR_ID environment variable
func dockerExtractAuroraTagsFromExecId(execId string) (auroraTags map[string]string) {

	// Regex expression to parse MESOS_EXECUTOR_ID env var in to usable tags
	var exp = `(?P<executor>^[a-zA-Z0-9]+)-` +
		`(?P<role>[a-zA-Z0-9_\-]+)-` +
		`(?P<stage>devel|staging[0-9]+|prod)-` +
		`(?P<job>[a-zA-Z0-9_\-]+)-` +
		`(?P<instance>[0-9]+)-` +
		`(?P<id>[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$)`

	auroraTags = utils.RegexGroupsToMap(exp, execId)

	// Add full MESOS_EXECUTOR_ID value as Aurora task tag
	auroraTags["task"] = execId

	// Confirm complete regex match for all keys before setting tags (empty map if fail)
	var auroraKeys = [7]string{"executor", "role", "stage", "job", "instance", "id", "task"}

	for _, key := range auroraKeys {
		if _, present := auroraTags[string(key)]; !present {
			auroraTags = map[string]string{}
		}
	}

	return auroraTags
}

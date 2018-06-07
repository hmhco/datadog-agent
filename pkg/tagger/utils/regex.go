package utils

import (
	"regexp"
)

func RegexGroupsToMap(exp, str string) (groupsMap map[string]string) {

	var compRegEx = regexp.MustCompile(exp)
	match := compRegEx.FindStringSubmatch(str)

	groupsMap = make(map[string]string)
	for i, name := range compRegEx.SubexpNames() {
		if i > 0 && i <= len(match) {
			groupsMap[name] = match[i]
		}
	}
	return groupsMap
}

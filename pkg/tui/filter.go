package tui

import (
	"fmt"
	"regexp"

	"github.com/solo-io/bumblebee/pkg/loader"
)

func (a *App) filterMatch(entry loader.MapEntry) bool {
	if a.filter == nil {
		// no filter, allow entry
		return true
	}
	if entry.Name != a.filter.MapName {
		// we have a filter, but this entry is for a different map
		// TODO: support multiple filters, for multiple maps
		return true
	}
	for k, v := range entry.Entry.Key {
		if k == a.filter.KeyField {
			if a.filter.Regex.MatchString(v) {
				return true
			}
		}
	}
	return false
}

func BuildFilter(filterString []string, watchedMaps map[string]loader.WatchedMap) (*Filter, error) {
	if len(filterString) == 0 {
		return nil, nil
	}
	if len(filterString) != 3 {
		return nil, fmt.Errorf("filter syntax error, should have 3 fields, found %v", len(filterString))
	}

	mapName := filterString[0]
	labelName := filterString[1]

	if _, ok := watchedMaps[mapName]; !ok {
		return nil, fmt.Errorf("didnt find map '%v'", mapName)
	}
	var foundKeyName bool
	for _, v := range watchedMaps[mapName].Labels {
		if v == labelName {
			foundKeyName = true
		}
	}
	if !foundKeyName {
		return nil, fmt.Errorf("didnt find key val '%v'", labelName)
	}

	regex := regexp.MustCompile(filterString[2])
	filter := &Filter{
		MapName:  mapName,
		KeyField: labelName,
		Regex:    regex,
	}
	return filter, nil
}

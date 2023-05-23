package tui

import (
	"fmt"
	"regexp"

	"github.com/solo-io/bumblebee/pkg/loader/mapwatcher"
)

func (a *App) filterMatch(entry mapwatcher.MapEntry) bool {
	if a.filter == nil {
		// no filters defined, allow entry
		return true
	}
	filter, ok := a.filter[entry.Name]
	if !ok {
		// we don't have a filter for this entry's map, allow entry
		return true
	}
	for k, v := range entry.Entry.Key {
		if k == filter.KeyField {
			if filter.Regex.MatchString(v) {
				return true
			}
		}
	}
	return false
}

func BuildFilter(filterString []string, watchedMaps map[string]mapwatcher.WatchedMap) (map[string]Filter, error) {
	if len(filterString) == 0 {
		return nil, nil
	}
	if (len(filterString) % 3) != 0 {
		return nil, fmt.Errorf("filter syntax error, each filter should have 3 fields, found %v fields total", len(filterString))
	}

	filterMap := make(map[string]Filter)
	numFilters := len(filterString) / 3
	for i := 0; i < numFilters; i++ {
		thisFilter := filterString[i*3 : i*3+3]
		mapName := thisFilter[0]
		labelName := thisFilter[1]

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

		regex := regexp.MustCompile(thisFilter[2])
		filterMap[mapName] = Filter{
			MapName:  mapName,
			KeyField: labelName,
			Regex:    regex,
		}
	}
	return filterMap, nil
}

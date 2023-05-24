package utils

import "strings"

type CaseInsensitiveMap[T any] struct {
	entries map[string]T
}

func NewCaseInsensitiveMap[T any](from *map[string]T) *CaseInsensitiveMap[T] {
	ciMap := &CaseInsensitiveMap[T]{}
	ciMap.initFrom(from)
	return ciMap
}

func (m *CaseInsensitiveMap[T]) Get(key string) (T, bool) {
	value, ok := m.entries[strings.ToLower(key)]
	return value, ok
}

func (m *CaseInsensitiveMap[T]) initFrom(entries *map[string]T) {
	m.entries = make(map[string]T)
	for key, value := range *entries {
		m.entries[strings.ToLower(key)] = value
	}
}

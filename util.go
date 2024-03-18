package main

import (
	"encoding/json"
	"os"
)

func check(err error) {
	if err != nil {
		panic(err)
	}
}

func must[T any](t T, err error) T {
	check(err)
	return t
}

func writeFile(name string, data []byte) {
	check(os.WriteFile(name, data, filePermissions))
}

func toJson(v any) []byte {
	jsonBytes := must(json.MarshalIndent(&v, "", "  "))
	jsonBytes = append(jsonBytes, byte('\n'))
	return jsonBytes
}

func fromJson[T any](data []byte) T {
	var t T
	check(json.Unmarshal(data, &t))
	return t
}

func WriteJsonFile(filepath string, t any) {
	jsonBytes := must(json.MarshalIndent(&t, "", "  "))
	jsonBytes = append(jsonBytes, byte('\n'))
	os.WriteFile(filepath, jsonBytes, 0660)
}

func filter[T any](ts []T, fn func(t T) bool) []T {
	var newTs []T
	for _, t := range ts {
		if !fn(t) {
			newTs = append(newTs, t)
		}
	}
	return newTs
}

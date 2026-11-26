package main

import (
	"reflect"
	"testing"
)

func TestFilterArgs(t *testing.T) {
	input := []string{"-mthreads", "-m64", "-ffile-prefix-map=C:/Program Files/Go=.", "-Wl", "option", "path with spaces.c", "-mthreads"}
	want := []string{"-m64", "-ffile-prefix-map=C:/Program Files/Go=.", "-Wl", "option", "path with spaces.c"}
	if got := filterArgs(input); !reflect.DeepEqual(got, want) {
		t.Fatalf("filterArgs() = %q, want %q", got, want)
	}
}

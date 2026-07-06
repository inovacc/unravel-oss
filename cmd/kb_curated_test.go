package cmd

import "testing"

func TestKbCuratedRegistered(t *testing.T) {
	var foundList, foundGet bool
	for _, c := range kbCuratedCmd.Commands() {
		if c.Name() == "list" {
			foundList = true
		}
		if c.Name() == "get" {
			foundGet = true
		}
	}
	if !foundList || !foundGet {
		t.Fatalf("kb curated must have list+get subcommands (list=%v get=%v)", foundList, foundGet)
	}
}

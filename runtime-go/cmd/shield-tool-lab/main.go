package main

import (
	"encoding/json"
	"github.com/LumosLab-Innovation/OpenShieldAI/runtime/toolguard"
	"os"
)

func main() {
	if len(os.Args) != 1 {
		json.NewEncoder(os.Stdout).Encode(map[string]string{"schemaVersion": "tool_guard_trial_v1", "status": "failed", "errorCode": "INVALID_ARGUMENTS"})
		os.Exit(1)
	}
	report, err := toolguard.RunTrial()
	json.NewEncoder(os.Stdout).Encode(report)
	if err != nil {
		os.Exit(1)
	}
}

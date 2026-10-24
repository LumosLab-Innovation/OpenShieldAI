package main

import (
	"encoding/json"
	"io"
	"os"
	"runtime/debug"

	correlation "github.com/LumosLab-Innovation/OpenShieldAI/runtime"
)

func main() {
	defer func() {
		if recover() != nil {
			json.NewEncoder(os.Stdout).Encode(map[string]any{"schemaVersion": "correlation_result_v1", "status": "failed", "errorCode": "INTERNAL_ERROR", "isFinding": false})
			os.Exit(1)
		}
	}()
	debug.SetMemoryLimit(64 << 20) // Soft GC target; not an OS memory sandbox.
	data, err := io.ReadAll(io.LimitReader(os.Stdin, correlation.MaxInput+1))
	code := "INVALID_REQUEST"
	if len(data) > correlation.MaxInput {
		code = "INPUT_LIMIT"
	}
	var result any
	if err == nil && len(data) <= correlation.MaxInput {
		result, err = correlation.Analyze(data)
		if err != nil {
			code = err.Error()
		}
	}
	if result == nil || err != nil || len(data) > correlation.MaxInput {
		json.NewEncoder(os.Stdout).Encode(map[string]any{"schemaVersion": "correlation_result_v1", "status": "failed", "errorCode": code, "isFinding": false})
		os.Exit(1)
	}
	json.NewEncoder(os.Stdout).Encode(result)
}

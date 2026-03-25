// Copyright 2026 Erst Users
// SPDX-License-Identifier: Apache-2.0

package simulator

type DiagnosticEvent struct {
	EventType                string   `json:"event_type"`
	ContractID               *string  `json:"contract_id,omitempty"`
	Topics                   []string `json:"topics"`
	Data                     string   `json:"data"`
	InSuccessfulContractCall bool     `json:"in_successful_contract_call"`
	WasmInstruction          *string  `json:"wasm_instruction,omitempty"`
	CPU                      *uint64  `json:"cpu,omitempty"`
	Memory                   *uint64  `json:"mem,omitempty"`
}

type CategorizedEvent struct {
	Category string          `json:"category"`
	Event    DiagnosticEvent `json:"event"`
}

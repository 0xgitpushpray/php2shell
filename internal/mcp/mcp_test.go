package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/0xgitpushpray/php2shell/internal/advisory"
)

func TestServe(t *testing.T) {
	a, err := advisory.Embedded()
	if err != nil {
		t.Fatal(err)
	}
	in := strings.Join([]string{
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`,
		`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"check_version","arguments":{"version":"8.3.12"}}}`,
		`{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"check_version","arguments":{}}}`,
		`{"jsonrpc":"2.0","id":5,"method":"nope"}`,
		`not json`,
	}, "\n")
	var out bytes.Buffer
	s := &Server{Advisory: a, Version: "test"}
	if err := s.Serve(context.Background(), strings.NewReader(in), &out); err != nil {
		t.Fatal(err)
	}

	var resps []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(out.String()), "\n") {
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatalf("bad response line %q: %v", line, err)
		}
		resps = append(resps, m)
	}
	if len(resps) != 6 { // the notification gets no response
		t.Fatalf("got %d responses:\n%s", len(resps), out.String())
	}

	init := resps[0]["result"].(map[string]any)
	if init["protocolVersion"] != "2025-03-26" {
		t.Errorf("initialize should echo the protocol version: %v", init)
	}
	if n := len(resps[1]["result"].(map[string]any)["tools"].([]any)); n != 4 {
		t.Errorf("tools/list returned %d tools", n)
	}
	call := resps[2]["result"].(map[string]any)
	text := call["content"].([]any)[0].(map[string]any)["text"].(string)
	if call["isError"] != false || !strings.Contains(text, `"status":"vulnerable"`) {
		t.Errorf("check_version result: %v", call)
	}
	if resps[3]["result"].(map[string]any)["isError"] != true {
		t.Error("missing argument should be a tool error")
	}
	if resps[4]["error"].(map[string]any)["code"].(float64) != -32601 {
		t.Error("unknown method should return -32601")
	}
	if resps[5]["error"].(map[string]any)["code"].(float64) != -32700 {
		t.Error("invalid JSON should return -32700")
	}
}

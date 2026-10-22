// Package mcp exposes php2shell to AI agents as a Model Context Protocol
// server over stdio (newline-delimited JSON-RPC 2.0).
package mcp

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"

	"github.com/0xgitpushpray/php2shell/internal/advisory"
	"github.com/0xgitpushpray/php2shell/internal/assess"
	"github.com/0xgitpushpray/php2shell/internal/local"
	"github.com/0xgitpushpray/php2shell/internal/remote"
	"github.com/0xgitpushpray/php2shell/internal/report"
)

const latestProtocol = "2025-06-18"

// Server answers MCP requests.
type Server struct {
	Advisory *advisory.Advisory
	Version  string
	Remote   remote.Options
	Local    local.Options
}

type request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type response struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type tool struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	InputSchema map[string]any `json:"inputSchema"`
}

func object(props map[string]any, required ...string) map[string]any {
	s := map[string]any{"type": "object", "properties": props}
	if len(required) > 0 {
		s["required"] = required
	}
	return s
}

var tools = []tool{
	{
		Name:        "check_url",
		Description: "Check whether a website's exposed PHP version is vulnerable to PHP2Shell (CVE-2026-109618, CVE-2026-109619). Reads response headers only; no exploit traffic.",
		InputSchema: object(map[string]any{
			"url":  map[string]any{"type": "string", "description": "Website URL or host name"},
			"deep": map[string]any{"type": "boolean", "description": "Also probe /index.php and retry with GET"},
		}, "url"),
	},
	{
		Name:        "check_version",
		Description: "Classify a PHP version string (e.g. 8.3.12 or 8.1.2-1ubuntu2.14) against the PHP2Shell advisory. Instant and offline.",
		InputSchema: object(map[string]any{
			"version": map[string]any{"type": "string", "description": "PHP version, e.g. from `php -v`"},
		}, "version"),
	},
	{
		Name:        "scan_local",
		Description: "Inventory every PHP installation on the machine running this server (CLI, php-fpm, mod_php, LiteSpeed, FrankenPHP), including distro backports and workers that need a restart.",
		InputSchema: object(map[string]any{}),
	},
	{
		Name:        "advisory",
		Description: "Return the PHP2Shell advisory data: CVEs, fixed releases per branch, mitigations and references.",
		InputSchema: object(map[string]any{}),
	},
}

// Serve reads requests from in and writes responses to out until in closes.
func (s *Server) Serve(ctx context.Context, in io.Reader, out io.Writer) error {
	sc := bufio.NewScanner(in)
	sc.Buffer(make([]byte, 0, 64*1024), 10<<20)
	enc := json.NewEncoder(out)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		var req request
		if err := json.Unmarshal(line, &req); err != nil {
			if err := enc.Encode(response{JSONRPC: "2.0", ID: json.RawMessage("null"), Error: &rpcError{-32700, "parse error"}}); err != nil {
				return err
			}
			continue
		}
		if len(req.ID) == 0 {
			continue // notification
		}
		resp := response{JSONRPC: "2.0", ID: req.ID}
		resp.Result, resp.Error = s.handle(ctx, req)
		if err := enc.Encode(resp); err != nil {
			return err
		}
	}
	return sc.Err()
}

func (s *Server) handle(ctx context.Context, req request) (any, *rpcError) {
	switch req.Method {
	case "initialize":
		var p struct {
			ProtocolVersion string `json:"protocolVersion"`
		}
		json.Unmarshal(req.Params, &p)
		if p.ProtocolVersion == "" {
			p.ProtocolVersion = latestProtocol
		}
		return map[string]any{
			"protocolVersion": p.ProtocolVersion,
			"capabilities":    map[string]any{"tools": map[string]any{}},
			"serverInfo":      map[string]any{"name": "php2shell", "version": s.Version},
			"instructions":    "Use check_version when you already know the PHP version (cheapest), check_url for a website, scan_local for the machine this server runs on.",
		}, nil
	case "ping":
		return map[string]any{}, nil
	case "tools/list":
		return map[string]any{"tools": tools}, nil
	case "tools/call":
		var p struct {
			Name      string          `json:"name"`
			Arguments json.RawMessage `json:"arguments"`
		}
		if err := json.Unmarshal(req.Params, &p); err != nil {
			return nil, &rpcError{-32602, "invalid params"}
		}
		payload, err := s.call(ctx, p.Name, p.Arguments)
		if err != nil {
			return toolResult(err.Error(), true), nil
		}
		text, _ := json.Marshal(payload)
		return toolResult(string(text), false), nil
	}
	return nil, &rpcError{-32601, "method not found: " + req.Method}
}

func toolResult(text string, isError bool) map[string]any {
	return map[string]any{
		"content": []map[string]any{{"type": "text", "text": text}},
		"isError": isError,
	}
}

func (s *Server) call(ctx context.Context, name string, raw json.RawMessage) (any, error) {
	var args struct {
		URL     string `json:"url"`
		Deep    bool   `json:"deep"`
		Version string `json:"version"`
	}
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &args); err != nil {
			return nil, fmt.Errorf("invalid arguments: %w", err)
		}
	}
	switch name {
	case "check_url":
		if args.URL == "" {
			return nil, fmt.Errorf("url is required")
		}
		opt := s.Remote
		opt.Deep = opt.Deep || args.Deep
		return remote.New(s.Advisory, opt).Check(ctx, args.URL), nil
	case "check_version":
		if args.Version == "" {
			return nil, fmt.Errorf("version is required")
		}
		return report.Result{Kind: "version", Target: args.Version, Verdict: assess.Classify(s.Advisory, args.Version)}, nil
	case "scan_local":
		results, notes := local.Run(ctx, s.Advisory, s.Local)
		return map[string]any{"results": results, "notes": notes}, nil
	case "advisory":
		return s.Advisory, nil
	}
	return nil, fmt.Errorf("unknown tool %q", name)
}

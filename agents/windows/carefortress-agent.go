package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"strings"
	"time"
)

const (
	hmacKeyFile       = `C:\ProgramData\CareFortress\agent.key`
	heartbeatInterval = 5 * time.Second
)

var (
	agentSeq  int64
	agentHash string
	hmacKey   []byte
	hostname  string
)

// pythonJSON replicates Python's json.dumps(sort_keys=True)
// Go map marshaling is already alphabetically sorted; this adds Python's ", " and ": " spacing
func pythonJSON(payload map[string]interface{}) []byte {
	compact, _ := json.Marshal(payload)
	var result strings.Builder
	inString := false
	escaped := false
	for _, c := range string(compact) {
		if escaped {
			result.WriteRune(c)
			escaped = false
			continue
		}
		if c == '\\' && inString {
			result.WriteRune(c)
			escaped = true
			continue
		}
		if c == '"' {
			inString = !inString
		}
		result.WriteRune(c)
		if !inString && (c == ':' || c == ',') {
			result.WriteRune(' ')
		}
	}
	return []byte(result.String())
}

func signPayload(payload map[string]interface{}) string {
	data := pythonJSON(payload)
	mac := hmac.New(sha256.New, hmacKey)
	mac.Write(data)
	return hex.EncodeToString(mac.Sum(nil))
}

func loadHMACKey() error {
	data, err := os.ReadFile(hmacKeyFile)
	if err != nil {
		return fmt.Errorf("cannot read HMAC key: %w", err)
	}
	hmacKey = []byte(strings.TrimSpace(string(data)))
	return nil
}

func computeAgentHash() string {
	exePath, err := os.Executable()
	if err != nil {
		return "unknown"
	}
	data, err := os.ReadFile(exePath)
	if err != nil {
		return "unknown"
	}
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

func findVirtioPort() (string, error) {
	portName := fmt.Sprintf(`\\.\Global\log.%s`, hostname)
	f, err := os.OpenFile(portName, os.O_RDWR, 0)
	if err == nil {
		f.Close()
		return portName, nil
	}
	for i := 3; i <= 9; i++ {
		portName = fmt.Sprintf(`\\.\COM%d`, i)
		f, err := os.OpenFile(portName, os.O_RDWR, 0)
		if err == nil {
			f.Close()
			return portName, nil
		}
	}
	return "", fmt.Errorf("no virtio serial port found")
}

func writeEntry(port *os.File, entryType, msg string, extra map[string]interface{}) error {
	agentSeq++
	payload := map[string]interface{}{
		"ts":        time.Now().UTC().Format(time.RFC3339Nano),
		"host":      hostname,
		"type":      entryType,
		"msg":       msg,
		"agent_seq": agentSeq,
	}
	for k, v := range extra {
		payload[k] = v
	}
	sig := signPayload(payload)
	payload["agent_hmac"] = sig
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	data = append(data, '\n')
	_, err = port.Write(data)
	return err
}

func main() {
	var err error
	hostname, err = os.Hostname()
	if err != nil {
		hostname = "unknown-windows"
	}

	if err := loadHMACKey(); err != nil {
		fmt.Fprintf(os.Stderr, "FATAL: %v\n", err)
		os.Exit(1)
	}

	agentHash = computeAgentHash()
	fmt.Printf("CareFortress Agent starting on %s (Go %s/%s)\n", hostname, runtime.GOOS, runtime.GOARCH)
	fmt.Printf("Agent hash: %s...\n", agentHash[:16])

	var portPath string
	for i := 0; i < 30; i++ {
		portPath, err = findVirtioPort()
		if err == nil {
			break
		}
		fmt.Fprintf(os.Stderr, "waiting for virtio port... (%d/30)\n", i+1)
		time.Sleep(1 * time.Second)
	}
	if portPath == "" {
		fmt.Fprintf(os.Stderr, "FATAL: virtio serial port not found after 30s\n")
		os.Exit(1)
	}

	port, err := os.OpenFile(portPath, os.O_RDWR, 0)
	if err != nil {
		fmt.Fprintf(os.Stderr, "FATAL: cannot open %s: %v\n", portPath, err)
		os.Exit(1)
	}
	defer port.Close()

	fmt.Printf("Connected to virtio port: %s\n", portPath)
	writeEntry(port, "AGENT_START", fmt.Sprintf("CareFortress Windows agent started (%s)", runtime.GOARCH), nil)

	for {
		time.Sleep(heartbeatInterval)
		extra := map[string]interface{}{
			"load_1m":    "0.00",
			"agent_hash": agentHash,
		}
		if err := writeEntry(port, "HEARTBEAT", "periodic check", extra); err != nil {
			fmt.Fprintf(os.Stderr, "write error: %v -- reconnecting\n", err)
			port.Close()
			time.Sleep(2 * time.Second)
			port, err = os.OpenFile(portPath, os.O_RDWR, 0)
			if err != nil {
				fmt.Fprintf(os.Stderr, "reconnect failed: %v\n", err)
			}
		}
	}
}

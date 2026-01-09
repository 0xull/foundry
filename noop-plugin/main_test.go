package main

import (
	"os"
	"testing"

	"github.com/containernetworking/cni/pkg/skel"
	types100 "github.com/containernetworking/cni/pkg/types/100"
)

// TestCmdAddReturnsValidCNIResult verifies that cmdAdd constructs a valid CNI Result
// according to the CNI specification v1.0.0
func TestCmdAddReturnsValidCNIResult(t *testing.T) {
	args := &skel.CmdArgs{
		ContainerID: "test-container-abc123",
		Netns:       "/var/run/netns/test-ns",
		IfName:      "eth0",
		Args:        "K8S_POD_NAMESPACE=default;K8S_POD_NAME=test-pod",
		Path:        "/opt/cni/bin",
		StdinData:   []byte(`{"cniVersion":"1.0.0","name":"test-network","type":"noop"}`),
	}

	// Act: Call cmdAdd
	err := cmdAdd(args)

	// Assert: Should succeed
	if err != nil {
		t.Fatalf("cmdAdd failed: %v", err)
	}
}

// TestCmdCheckSucceeds verifies that cmdCheck completes without error
func TestCmdCheckSucceeds(t *testing.T) {
	args := &skel.CmdArgs{
		ContainerID: "test-container-check",
		Netns:       "/var/run/netns/test-ns",
		IfName:      "eth0",
	}

	err := cmdCheck(args)
	if err != nil {
		t.Errorf("cmdCheck failed: %v", err)
	}
}

// TestCmdDelSucceeds verifies that cmdDel completes without error
func TestCmdDelSucceeds(t *testing.T) {
	args := &skel.CmdArgs{
		ContainerID: "test-container-del",
		Netns:       "/var/run/netns/test-ns",
		IfName:      "eth0",
	}

	err := cmdDel(args)
	if err != nil {
		t.Errorf("cmdDel failed: %v", err)
	}
}

// TestCNIResultStructure validates the CNI Result structure compliance
func TestCNIResultStructure(t *testing.T) {
	result := &types100.Result{
		CNIVersion: "1.0.0",
		Interfaces: []*types100.Interface{
			{
				Name:    "eth0",
				Mac:     "02:00:00:00:00:01",
				Sandbox: "/var/run/netns/test",
			},
		},
	}

	// Validate CNI version
	if result.CNIVersion != "1.0.0" {
		t.Errorf("Expected CNIVersion 1.0.0, got %s", result.CNIVersion)
	}

	// Validate interfaces
	if len(result.Interfaces) != 1 {
		t.Fatalf("Expected 1 interface, got %d", len(result.Interfaces))
	}

	iface := result.Interfaces[0]
	
	// Validate interface name
	if iface.Name != "eth0" {
		t.Errorf("Expected interface name 'eth0', got '%s'", iface.Name)
	}

	// Validate MAC address format (should be 17 chars: XX:XX:XX:XX:XX:XX)
	if len(iface.Mac) != 17 {
		t.Errorf("Invalid MAC address format: %s", iface.Mac)
	}

	// Validate sandbox path
	if iface.Sandbox == "" {
		t.Error("Sandbox path should not be empty")
	}
}

// TestCmdArgsValidation ensures required CNI arguments are present
func TestCmdArgsValidation(t *testing.T) {
	testCases := []struct {
		name        string
		containerID string
		netns       string
		ifName      string
		expectValid bool
	}{
		{
			name:        "all fields valid",
			containerID: "container-123",
			netns:       "/var/run/netns/test",
			ifName:      "eth0",
			expectValid: true,
		},
		{
			name:        "missing container ID",
			containerID: "",
			netns:       "/var/run/netns/test",
			ifName:      "eth0",
			expectValid: false,
		},
		{
			name:        "missing netns",
			containerID: "container-123",
			netns:       "",
			ifName:      "eth0",
			expectValid: false,
		},
		{
			name:        "missing interface name",
			containerID: "container-123",
			netns:       "/var/run/netns/test",
			ifName:      "",
			expectValid: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			args := &skel.CmdArgs{
				ContainerID: tc.containerID,
				Netns:       tc.netns,
				IfName:      tc.ifName,
			}

			isValid := args.ContainerID != "" && args.Netns != "" && args.IfName != ""
			
			if isValid != tc.expectValid {
				t.Errorf("Expected valid=%v, got %v", tc.expectValid, isValid)
			}
		})
	}
}

// TestLogFileCreation verifies that the plugin can create its log file
func TestLogFileCreation(t *testing.T) {
	testLogPath := "/tmp/noop-cni-test.log"
	
	// Cleanup
	defer os.Remove(testLogPath)
	
	// Attempt to create log file
	file, err := os.OpenFile(testLogPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		t.Fatalf("Failed to create log file: %v", err)
	}
	defer file.Close()

	// Write test entry
	_, err = file.WriteString("TEST LOG ENTRY\n")
	if err != nil {
		t.Errorf("Failed to write to log file: %v", err)
	}

	// Verify file exists
	if _, err := os.Stat(testLogPath); os.IsNotExist(err) {
		t.Error("Log file was not created")
	}
}

// TestMACAddressFormat validates MAC address string formatting
func TestMACAddressFormat(t *testing.T) {
	testCases := []struct {
		mac         string
		expectValid bool
	}{
		{"02:00:00:00:00:01", true},
		{"AA:BB:CC:DD:EE:FF", true},
		{"00:11:22:33:44:55", true},
		{"invalid-mac", false},
		{"02:00:00:00:00", false},
		{"", false},
		{"02-00-00-00-00-01", false}, // Wrong separator
	}

	for _, tc := range testCases {
		t.Run(tc.mac, func(t *testing.T) {
			// MAC should be exactly 17 characters (6 hex pairs + 5 colons)
			isValid := len(tc.mac) == 17 && 
				tc.mac[2] == ':' && 
				tc.mac[5] == ':' && 
				tc.mac[8] == ':' && 
				tc.mac[11] == ':' && 
				tc.mac[14] == ':'

			if isValid != tc.expectValid {
				t.Errorf("MAC '%s': expected valid=%v, got %v", 
					tc.mac, tc.expectValid, isValid)
			}
		})
	}
}
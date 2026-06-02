package collector

import (
	"os"
	"os/exec"
	"strings"
)

type HostInfo struct {
	Hostname  string `json:"hostname"`
	OS        string `json:"os"`
	OSVersion string `json:"os_version"`
	Kernel    string `json:"kernel"`
	Arch      string `json:"arch"`
	Uptime    string `json:"uptime"`
}

func CollectHostInfo() (HostInfo, error) {
	info := HostInfo{}

	if hostname, err := os.Hostname(); err == nil {
		info.Hostname = hostname
	}

	if out, err := exec.Command("uname", "-r").Output(); err == nil {
		info.Kernel = strings.TrimSpace(string(out))
	}

	if out, err := exec.Command("uname", "-m").Output(); err == nil {
		info.Arch = strings.TrimSpace(string(out))
	}

	if data, err := os.ReadFile("/etc/os-release"); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			switch {
			case strings.HasPrefix(line, "NAME="):
				info.OS = strings.Trim(strings.TrimPrefix(line, "NAME="), `"`)
			case strings.HasPrefix(line, "VERSION="):
				info.OSVersion = strings.Trim(strings.TrimPrefix(line, "VERSION="), `"`)
			case strings.HasPrefix(line, "PRETTY_NAME=") && info.OS == "":
				info.OS = strings.Trim(strings.TrimPrefix(line, "PRETTY_NAME="), `"`)
			}
		}
	}

	if out, err := exec.Command("uptime", "-p").Output(); err == nil {
		info.Uptime = strings.TrimSpace(string(out))
	}

	return info, nil
}

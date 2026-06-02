package collector

import (
	"bufio"
	"bytes"
	"os/exec"
	"strings"
)

type Package struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Arch    string `json:"arch,omitempty"`
}

func CollectPackages() ([]Package, error) {
	if pkgs, err := collectDpkg(); err == nil && len(pkgs) > 0 {
		return pkgs, nil
	}
	if pkgs, err := collectRpm(); err == nil && len(pkgs) > 0 {
		return pkgs, nil
	}
	if pkgs, err := collectApk(); err == nil && len(pkgs) > 0 {
		return pkgs, nil
	}
	return nil, nil
}

func collectDpkg() ([]Package, error) {
	out, err := exec.Command("dpkg-query", "-W", "-f=${Package}\t${Version}\t${Architecture}\n").Output()
	if err != nil {
		return nil, err
	}
	var pkgs []Package
	scanner := bufio.NewScanner(bytes.NewReader(out))
	for scanner.Scan() {
		parts := strings.Split(scanner.Text(), "\t")
		if len(parts) >= 2 {
			p := Package{Name: parts[0], Version: parts[1]}
			if len(parts) >= 3 {
				p.Arch = parts[2]
			}
			pkgs = append(pkgs, p)
		}
	}
	return pkgs, nil
}

func collectRpm() ([]Package, error) {
	out, err := exec.Command("rpm", "-qa", "--queryformat", "%{NAME}\t%{VERSION}-%{RELEASE}\t%{ARCH}\n").Output()
	if err != nil {
		return nil, err
	}
	var pkgs []Package
	scanner := bufio.NewScanner(bytes.NewReader(out))
	for scanner.Scan() {
		parts := strings.Split(scanner.Text(), "\t")
		if len(parts) >= 2 {
			p := Package{Name: parts[0], Version: parts[1]}
			if len(parts) >= 3 {
				p.Arch = parts[2]
			}
			pkgs = append(pkgs, p)
		}
	}
	return pkgs, nil
}

func collectApk() ([]Package, error) {
	out, err := exec.Command("apk", "info", "-v").Output()
	if err != nil {
		return nil, err
	}
	var pkgs []Package
	scanner := bufio.NewScanner(bytes.NewReader(out))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		// format: name-version
		idx := strings.LastIndex(line, "-")
		if idx > 0 {
			pkgs = append(pkgs, Package{Name: line[:idx], Version: line[idx+1:]})
		} else {
			pkgs = append(pkgs, Package{Name: line})
		}
	}
	return pkgs, nil
}

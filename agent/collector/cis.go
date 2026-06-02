package collector

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

type CISCheck struct {
	ID       string `json:"id"`
	Title    string `json:"title"`
	Status   string `json:"status"`   // PASS | FAIL | WARN | ERROR
	Evidence string `json:"evidence"`
	Severity string `json:"severity"` // high | medium | low
}

func RunCISChecks() []CISCheck {
	checks := []func() CISCheck{
		checkPasswordComplexity,
		checkPasswordExpiration,
		checkRootSSHLogin,
		checkUnusedFilesystems,
		checkFirewall,
		checkTimeSynchronization,
		checkAuditd,
		checkAppArmorSELinux,
		checkWorldWritableFiles,
		checkGDMAutoLogin,
		checkSSHProtocol,
		checkAIDE,
	}
	results := make([]CISCheck, 0, len(checks))
	for _, fn := range checks {
		results = append(results, fn())
	}
	return results
}

// CIS 5.3.1 — password complexity via PAM
func checkPasswordComplexity() CISCheck {
	c := CISCheck{
		ID:       "CIS-5.3.1",
		Title:    "Password complexity enforced (pam_pwquality)",
		Severity: "high",
	}
	pamFiles := []string{
		"/etc/pam.d/common-password",
		"/etc/pam.d/system-auth",
		"/etc/pam.d/password-auth",
	}
	for _, f := range pamFiles {
		data, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		content := string(data)
		if strings.Contains(content, "pam_pwquality") || strings.Contains(content, "pam_cracklib") {
			c.Status = "PASS"
			c.Evidence = fmt.Sprintf("pam_pwquality/pam_cracklib found in %s", f)
			return c
		}
	}
	// Also check /etc/security/pwquality.conf
	if _, err := os.Stat("/etc/security/pwquality.conf"); err == nil {
		data, _ := os.ReadFile("/etc/security/pwquality.conf")
		if strings.Contains(string(data), "minlen") {
			c.Status = "PASS"
			c.Evidence = "pwquality.conf with minlen configured"
			return c
		}
	}
	c.Status = "FAIL"
	c.Evidence = "pam_pwquality/pam_cracklib not found in PAM config"
	return c
}

// CIS 5.4.1.1 — password max age
func checkPasswordExpiration() CISCheck {
	c := CISCheck{
		ID:       "CIS-5.4.1.1",
		Title:    "Password maximum age ≤ 365 days",
		Severity: "medium",
	}
	data, err := os.ReadFile("/etc/login.defs")
	if err != nil {
		c.Status = "ERROR"
		c.Evidence = "Cannot read /etc/login.defs"
		return c
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "PASS_MAX_DAYS") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				var days int
				fmt.Sscanf(parts[1], "%d", &days)
				if days > 0 && days <= 365 {
					c.Status = "PASS"
					c.Evidence = fmt.Sprintf("PASS_MAX_DAYS = %d", days)
				} else {
					c.Status = "FAIL"
					c.Evidence = fmt.Sprintf("PASS_MAX_DAYS = %d (should be ≤ 365)", days)
				}
				return c
			}
		}
	}
	c.Status = "FAIL"
	c.Evidence = "PASS_MAX_DAYS not set in /etc/login.defs"
	return c
}

// CIS 5.2.8 — root SSH login disabled
func checkRootSSHLogin() CISCheck {
	c := CISCheck{
		ID:       "CIS-5.2.8",
		Title:    "Root login disabled over SSH",
		Severity: "high",
	}
	sshdFiles := []string{"/etc/ssh/sshd_config"}
	// Also check drop-in configs
	if entries, err := filepath.Glob("/etc/ssh/sshd_config.d/*.conf"); err == nil {
		sshdFiles = append(sshdFiles, entries...)
	}
	for _, f := range sshdFiles {
		data, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "#") {
				continue
			}
			if strings.HasPrefix(strings.ToLower(line), "permitrootlogin") {
				parts := strings.Fields(line)
				if len(parts) >= 2 {
					val := strings.ToLower(parts[1])
					if val == "no" || val == "prohibit-password" {
						c.Status = "PASS"
						c.Evidence = fmt.Sprintf("%s: %s", f, line)
					} else {
						c.Status = "FAIL"
						c.Evidence = fmt.Sprintf("%s: PermitRootLogin = %s (should be no)", f, parts[1])
					}
					return c
				}
			}
		}
	}
	c.Status = "WARN"
	c.Evidence = "PermitRootLogin not explicitly set (default may allow root)"
	return c
}

// CIS 1.1.1 — unused/risky filesystems disabled
func checkUnusedFilesystems() CISCheck {
	c := CISCheck{
		ID:       "CIS-1.1.1",
		Title:    "Unused filesystems (cramfs, squashfs, udf) disabled",
		Severity: "low",
	}
	dangerous := []string{"cramfs", "squashfs", "udf", "freevxfs", "jffs2", "hfs", "hfsplus"}
	loaded := []string{}
	blocked := []string{}

	for _, fs := range dangerous {
		// Check if loaded
		out, _ := exec.Command("lsmod").Output()
		if strings.Contains(string(out), fs) {
			loaded = append(loaded, fs)
			continue
		}
		// Check if blacklisted
		found := false
		modprobeFiles, _ := filepath.Glob("/etc/modprobe.d/*.conf")
		modprobeFiles = append(modprobeFiles, "/etc/modprobe.conf")
		for _, mf := range modprobeFiles {
			data, err := os.ReadFile(mf)
			if err != nil {
				continue
			}
			for _, line := range strings.Split(string(data), "\n") {
				if strings.Contains(line, "install "+fs+" /bin/true") ||
					strings.Contains(line, "blacklist "+fs) {
					found = true
					break
				}
			}
			if found {
				break
			}
		}
		if found {
			blocked = append(blocked, fs)
		}
	}

	if len(loaded) == 0 {
		c.Status = "PASS"
		c.Evidence = fmt.Sprintf("None of the risky filesystems are loaded. Blacklisted: %v", blocked)
	} else {
		c.Status = "FAIL"
		c.Evidence = fmt.Sprintf("Loaded risky filesystems: %v", loaded)
	}
	return c
}

// CIS 3.5.1 — firewall enabled
func checkFirewall() CISCheck {
	c := CISCheck{
		ID:       "CIS-3.5.1",
		Title:    "Firewall enabled and active (ufw/firewalld/iptables)",
		Severity: "high",
	}

	// Check ufw via systemctl (no root needed)
	if out, err := exec.Command("systemctl", "is-active", "ufw").Output(); err == nil {
		if strings.TrimSpace(string(out)) == "active" {
			c.Status = "PASS"
			c.Evidence = "ufw service is active (systemctl)"
			return c
		}
	}

	// Check ufw config file directly (no root needed)
	if data, err := os.ReadFile("/etc/ufw/ufw.conf"); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			if strings.TrimSpace(line) == "ENABLED=yes" {
				c.Status = "PASS"
				c.Evidence = "ufw enabled via /etc/ufw/ufw.conf"
				return c
			}
		}
	}

	// Check firewalld via systemctl
	if out, err := exec.Command("systemctl", "is-active", "firewalld").Output(); err == nil {
		if strings.TrimSpace(string(out)) == "active" {
			c.Status = "PASS"
			c.Evidence = "firewalld service is active"
			return c
		}
	}

	// Check firewall-cmd state
	if out, err := exec.Command("firewall-cmd", "--state").Output(); err == nil {
		if strings.TrimSpace(string(out)) == "running" {
			c.Status = "PASS"
			c.Evidence = "firewalld is running"
			return c
		}
	}

	// Check iptables has non-empty rules
	if out, err := exec.Command("iptables", "-L", "--line-numbers").Output(); err == nil {
		lines := strings.Split(strings.TrimSpace(string(out)), "\n")
		if len(lines) > 10 {
			c.Status = "PASS"
			c.Evidence = fmt.Sprintf("iptables has %d rule lines", len(lines))
			return c
		}
	}

	// Check nftables
	if out, err := exec.Command("nft", "list", "ruleset").Output(); err == nil {
		if len(strings.TrimSpace(string(out))) > 50 {
			c.Status = "PASS"
			c.Evidence = "nftables ruleset active"
			return c
		}
	}

	c.Status = "FAIL"
	c.Evidence = "No active firewall detected (checked ufw, firewalld, iptables, nftables)"
	return c
}

// CIS 2.2.1.1 — time synchronization
func checkTimeSynchronization() CISCheck {
	c := CISCheck{
		ID:       "CIS-2.2.1.1",
		Title:    "Time synchronization configured (chrony/ntpd/systemd-timesyncd)",
		Severity: "medium",
	}

	services := []string{"chronyd", "chrony", "ntpd", "ntp", "systemd-timesyncd"}
	for _, svc := range services {
		out, err := exec.Command("systemctl", "is-active", svc).Output()
		if err == nil && strings.TrimSpace(string(out)) == "active" {
			c.Status = "PASS"
			c.Evidence = fmt.Sprintf("%s is active", svc)
			return c
		}
	}

	// Check timedatectl
	if out, err := exec.Command("timedatectl", "status").Output(); err == nil {
		if strings.Contains(string(out), "NTP synchronized: yes") ||
			strings.Contains(string(out), "NTP service: active") {
			c.Status = "PASS"
			c.Evidence = "NTP synchronized via timedatectl"
			return c
		}
	}

	c.Status = "FAIL"
	c.Evidence = "No time synchronization service found active"
	return c
}

// CIS 4.1.1 — auditd running
func checkAuditd() CISCheck {
	c := CISCheck{
		ID:       "CIS-4.1.1",
		Title:    "Audit daemon (auditd) running",
		Severity: "medium",
	}
	out, err := exec.Command("systemctl", "is-active", "auditd").Output()
	if err == nil && strings.TrimSpace(string(out)) == "active" {
		c.Status = "PASS"
		c.Evidence = "auditd service is active"
		return c
	}
	// Check process directly
	if out2, err2 := exec.Command("pgrep", "auditd").Output(); err2 == nil && len(strings.TrimSpace(string(out2))) > 0 {
		c.Status = "PASS"
		c.Evidence = fmt.Sprintf("auditd process running (PID %s)", strings.TrimSpace(string(out2)))
		return c
	}
	c.Status = "FAIL"
	c.Evidence = "auditd is not running"
	return c
}

// CIS 1.6.1 — SELinux or AppArmor enabled
func checkAppArmorSELinux() CISCheck {
	c := CISCheck{
		ID:       "CIS-1.6.1",
		Title:    "SELinux or AppArmor MAC framework enabled",
		Severity: "high",
	}

	// AppArmor: kernel parameter (readable without root)
	if data, err := os.ReadFile("/sys/module/apparmor/parameters/enabled"); err == nil {
		if strings.TrimSpace(string(data)) == "Y" {
			c.Status = "PASS"
			c.Evidence = "AppArmor enabled (/sys/module/apparmor/parameters/enabled = Y)"
			return c
		}
	}

	// AppArmor: systemctl (no root needed)
	if out, err := exec.Command("systemctl", "is-active", "apparmor").Output(); err == nil {
		if strings.TrimSpace(string(out)) == "active" {
			c.Status = "PASS"
			c.Evidence = "AppArmor service is active (systemctl)"
			return c
		}
	}

	// AppArmor: aa-status (works if root or with sudo)
	if out, err := exec.Command("aa-status").Output(); err == nil {
		if strings.Contains(string(out), "profiles are loaded") {
			c.Status = "PASS"
			c.Evidence = "AppArmor: " + strings.Split(strings.TrimSpace(string(out)), "\n")[0]
			return c
		}
	}

	// SELinux: sestatus
	if out, err := exec.Command("sestatus").Output(); err == nil {
		if strings.Contains(string(out), "SELinux status:") && strings.Contains(string(out), "enabled") {
			c.Status = "PASS"
			c.Evidence = strings.TrimSpace(strings.Split(string(out), "\n")[0])
			return c
		}
	}

	// SELinux: config file
	if data, err := os.ReadFile("/etc/selinux/config"); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			if strings.HasPrefix(line, "SELINUX=") && !strings.Contains(line, "disabled") {
				c.Status = "PASS"
				c.Evidence = "SELinux: " + line
				return c
			}
		}
	}

	c.Status = "FAIL"
	c.Evidence = "Neither AppArmor nor SELinux appears to be enabled"
	return c
}

// CIS 6.1.10 — no world-writable files in key system dirs
func checkWorldWritableFiles() CISCheck {
	c := CISCheck{
		ID:       "CIS-6.1.10",
		Title:    "No world-writable files in system directories",
		Severity: "high",
	}

	dirs := []string{"/etc", "/usr", "/bin", "/sbin", "/lib", "/lib64"}
	wwFiles := []string{}

	for _, dir := range dirs {
		if _, err := os.Stat(dir); os.IsNotExist(err) {
			continue
		}
		out, err := exec.Command("find", dir, "-xdev", "-type", "f", "-perm", "-0002",
			"-not", "-path", "*/proc/*").Output()
		if err != nil {
			continue
		}
		for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
			if line != "" {
				wwFiles = append(wwFiles, line)
			}
		}
		if len(wwFiles) > 10 {
			break
		}
	}

	if len(wwFiles) == 0 {
		c.Status = "PASS"
		c.Evidence = "No world-writable files found in system directories"
	} else {
		c.Status = "FAIL"
		preview := wwFiles
		if len(preview) > 5 {
			preview = preview[:5]
		}
		c.Evidence = fmt.Sprintf("%d world-writable files found. First few: %s", len(wwFiles), strings.Join(preview, ", "))
	}
	return c
}

// CIS 1.8.2 — GDM auto-login disabled
func checkGDMAutoLogin() CISCheck {
	c := CISCheck{
		ID:       "CIS-1.8.2",
		Title:    "GDM/display manager auto-login disabled",
		Severity: "medium",
	}

	gdmFiles := []string{
		"/etc/gdm3/custom.conf",
		"/etc/gdm/custom.conf",
		"/etc/lightdm/lightdm.conf",
	}

	for _, f := range gdmFiles {
		data, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		content := string(data)
		if strings.Contains(content, "AutomaticLoginEnable=true") ||
			strings.Contains(content, "autologin-user=") {
			c.Status = "FAIL"
			c.Evidence = fmt.Sprintf("Auto-login enabled in %s", f)
			return c
		}
	}

	// GDM not installed is also acceptable
	if _, err := exec.Command("which", "gdm3").Output(); err != nil {
		if _, err2 := exec.Command("which", "gdm").Output(); err2 != nil {
			c.Status = "PASS"
			c.Evidence = "GDM/LightDM not installed"
			return c
		}
	}

	c.Status = "PASS"
	c.Evidence = "Auto-login not enabled in display manager config"
	return c
}

// CIS 5.2.4 — SSH Protocol 2 (modern sshd defaults to 2, check for forced downgrade)
func checkSSHProtocol() CISCheck {
	c := CISCheck{
		ID:       "CIS-5.2.4",
		Title:    "SSH uses Protocol 2 only",
		Severity: "high",
	}

	data, err := os.ReadFile("/etc/ssh/sshd_config")
	if err != nil {
		c.Status = "ERROR"
		c.Evidence = "Cannot read /etc/ssh/sshd_config"
		return c
	}

	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(strings.ToLower(line), "protocol") {
			parts := strings.Fields(line)
			if len(parts) >= 2 && parts[1] == "1" {
				c.Status = "FAIL"
				c.Evidence = "Protocol 1 explicitly enabled in sshd_config"
				return c
			}
		}
	}

	// Modern OpenSSH (7.0+) only supports Protocol 2 by default
	c.Status = "PASS"
	c.Evidence = "Protocol 1 not enabled; modern sshd defaults to Protocol 2"
	return c
}

// CIS 1.3.1 — AIDE or similar integrity checker installed
func checkAIDE() CISCheck {
	c := CISCheck{
		ID:       "CIS-1.3.1",
		Title:    "Filesystem integrity checker (AIDE/Tripwire) installed",
		Severity: "medium",
	}

	tools := []string{"aide", "tripwire", "samhain", "afick"}
	for _, tool := range tools {
		if out, err := exec.Command("which", tool).Output(); err == nil && len(strings.TrimSpace(string(out))) > 0 {
			c.Status = "PASS"
			c.Evidence = fmt.Sprintf("%s found at %s", tool, strings.TrimSpace(string(out)))
			return c
		}
	}

	// Check via dpkg/rpm
	if out, err := exec.Command("dpkg", "-l", "aide").Output(); err == nil && strings.Contains(string(out), "ii") {
		c.Status = "PASS"
		c.Evidence = "AIDE installed (dpkg)"
		return c
	}

	c.Status = "FAIL"
	c.Evidence = "No filesystem integrity checker found (aide, tripwire, samhain)"
	return c
}

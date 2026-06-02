# Build the Linux agent binary from Windows (cross-compile)
# Run: .\build.ps1
param(
    [string]$GOARCH = "amd64"  # change to "arm64" for Raspberry Pi / ARM
)

$env:GOOS   = "linux"
$env:GOARCH = $GOARCH
$env:CGO_ENABLED = "0"

Write-Host "[build] Cross-compiling Go agent for linux/$GOARCH..."
Push-Location "$PSScriptRoot\agent"
go build -ldflags="-s -w" -o "linux-agent" .
if ($LASTEXITCODE -ne 0) {
    Write-Error "[build] Build failed"
    Pop-Location
    exit 1
}
Pop-Location

Write-Host "[build] Done: agent\linux-agent"
Write-Host ""
Write-Host "Next steps:"
Write-Host "  1. Copy to your VM:  scp agent\linux-agent user@your-vm-ip:/tmp/"
Write-Host "  2. On the VM:        chmod +x /tmp/linux-agent"
Write-Host "  3. Test locally:     /tmp/linux-agent -output -"
Write-Host "  4. Send to AWS:      /tmp/linux-agent -endpoint https://YOUR-API.execute-api.region.amazonaws.com/prod"

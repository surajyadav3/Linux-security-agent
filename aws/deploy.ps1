# Deploy the full stack to AWS
# Prerequisites: aws CLI configured, Go installed
# Usage: .\deploy.ps1 -Region us-east-1

param(
    [string]$Region = "us-east-1",
    [string]$StackName = "linux-agent-stack"
)

$ROOT = $PSScriptRoot | Split-Path

Write-Host "[deploy] Step 1: Deploy CloudFormation stack..."
aws cloudformation deploy `
    --template-file "$PSScriptRoot\cloudformation.yaml" `
    --stack-name $StackName `
    --capabilities CAPABILITY_NAMED_IAM `
    --region $Region

if ($LASTEXITCODE -ne 0) { Write-Error "CloudFormation deploy failed"; exit 1 }

# Get the API endpoint from stack outputs
$API = aws cloudformation describe-stacks `
    --stack-name $StackName `
    --region $Region `
    --query "Stacks[0].Outputs[?OutputKey=='ApiEndpoint'].OutputValue" `
    --output text

Write-Host "[deploy] API Endpoint: $API"

Write-Host "[deploy] Step 2: Upload Lambda functions..."

# Package and upload ingest
Push-Location "$ROOT\lambda\ingest"
Compress-Archive -Force -Path "handler.py" -DestinationPath "ingest.zip"
aws lambda update-function-code `
    --function-name linux-agent-ingest `
    --zip-file fileb://ingest.zip `
    --region $Region | Out-Null
Remove-Item ingest.zip
Pop-Location
Write-Host "[deploy] Ingest Lambda updated"

# Package and upload query
Push-Location "$ROOT\lambda\query"
Compress-Archive -Force -Path "handler.py" -DestinationPath "query.zip"
aws lambda update-function-code `
    --function-name linux-agent-query `
    --zip-file fileb://query.zip `
    --region $Region | Out-Null
Remove-Item query.zip
Pop-Location
Write-Host "[deploy] Query Lambda updated"

Write-Host ""
Write-Host "============================================"
Write-Host " Deployment complete!"
Write-Host " API Endpoint: $API"
Write-Host "============================================"
Write-Host ""
Write-Host "On your Linux VM, run the agent with:"
Write-Host "  export AGENT_API_ENDPOINT=$API"
Write-Host "  ./linux-agent -endpoint `$AGENT_API_ENDPOINT"
Write-Host ""
Write-Host "Then open frontend/index.html in your browser and enter:"
Write-Host "  $API"

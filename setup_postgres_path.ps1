# PowerShell script to add PostgreSQL to PATH

# Find PostgreSQL installation
$pgInstallPath = ""
$possiblePaths = @(
    "C:\Program Files\PostgreSQL",
    "C:\PostgreSQL"
)

foreach ($basePath in $possiblePaths) {
    if (Test-Path $basePath) {
        # Find the latest version
        $versions = Get-ChildItem -Path $basePath -Directory | Sort-Object -Property Name -Descending
        if ($versions.Count -gt 0) {
            $pgInstallPath = Join-Path -Path $basePath -ChildPath $versions[0].Name
            break
        }
    }
}

if (-not $pgInstallPath) {
    Write-Host "PostgreSQL installation not found. Please install PostgreSQL first."
    exit 1
}

# Add PostgreSQL bin directory to PATH
$pgBinPath = Join-Path -Path $pgInstallPath -ChildPath "bin"
if (-not (Test-Path $pgBinPath)) {
    Write-Host "PostgreSQL bin directory not found at $pgBinPath"
    exit 1
}

# Check if already in PATH
$currentPath = [Environment]::GetEnvironmentVariable("PATH", "User")
if ($currentPath -like "*$pgBinPath*") {
    Write-Host "PostgreSQL is already in your PATH."
} else {
    # Add to PATH
    $newPath = "$currentPath;$pgBinPath"
    [Environment]::SetEnvironmentVariable("PATH", $newPath, "User")
    Write-Host "PostgreSQL has been added to your PATH."
    Write-Host "Please restart your terminal or PowerShell session for the changes to take effect."
}

# Test PostgreSQL connection
try {
    $env:Path = "$env:Path;$pgBinPath"
    $pgVersion = & "$pgBinPath\psql" --version
    Write-Host "PostgreSQL is installed and working: $pgVersion"
    
    # Create a test database for security testing
    Write-Host "Creating test database for security testing..."
    & "$pgBinPath\createdb" -U postgres postgres_security_test
    
    Write-Host "PostgreSQL setup complete!"
} catch {
    Write-Host "Error testing PostgreSQL: $_"
    Write-Host "Please make sure PostgreSQL service is running."
}

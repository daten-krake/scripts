<#
.SYNOPSIS
    Register an Azure AD App Registration with specified Microsoft Graph permissions using interactive login.

.PARAMETER Permissions
    Comma-separated list of Microsoft Graph permission names (e.g. "User.Read,Mail.Send,Directory.Read.All").

.PARAMETER DisplayName
    Display name for the app registration. Defaults to "App-<timestamp>".

.PARAMETER PermissionType
    Type of permissions to request: "Delegated" (default) or "Application".

.EXAMPLE
    ./app_reg.ps1 "User.Read,Mail.Send"
    ./app_reg.ps1 "User.Read.All,Directory.Read.All" -DisplayName "MyApp" -PermissionType Application
#>

param(
    [Parameter(Mandatory = $true, Position = 0)]
    [string]$Permissions,

    [Parameter(Position = 1)]
    [string]$DisplayName = "App-$(Get-Date -Format 'yyyyMMdd-HHmmss')",

    [Parameter()]
    [ValidateSet("Delegated", "Application")]
    [string]$PermissionType = "Delegated"
)

$ErrorActionPreference = "Stop"

# Microsoft Graph well-known application ID
$GraphAppId = "00000003-0000-0000-c000-000000000000"

# --- Ensure Microsoft.Graph module is available ---
if (-not (Get-Module -ListAvailable -Name Microsoft.Graph.Applications)) {
    Write-Host "Microsoft.Graph module not found. Installing..." -ForegroundColor Yellow
    Install-Module Microsoft.Graph -Scope CurrentUser -Force -AllowClobber
}

Import-Module Microsoft.Graph.Applications

# --- Interactive login ---
Write-Host "Connecting to Microsoft Graph (interactive login)..." -ForegroundColor Cyan
Connect-MgGraph -Scopes "Application.ReadWrite.All" -NoWelcome

# --- Resolve permission names to IDs ---
$requestedPerms = $Permissions -split "," | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne "" }

Write-Host "Looking up permission IDs for: $($requestedPerms -join ', ')" -ForegroundColor Cyan

$graphSp = Get-MgServicePrincipal -Filter "appId eq '$GraphAppId'"
if (-not $graphSp) {
    Write-Error "Could not find Microsoft Graph service principal in the tenant."
    exit 1
}

$resourceAccess = @()
$notFound = @()

foreach ($permName in $requestedPerms) {
    $found = $false

    if ($PermissionType -eq "Delegated") {
        $scope = $graphSp.Oauth2PermissionScopes | Where-Object { $_.Value -eq $permName }
        if ($scope) {
            $resourceAccess += @{ Id = $scope.Id; Type = "Scope" }
            $found = $true
        }
    }
    else {
        $role = $graphSp.AppRoles | Where-Object { $_.Value -eq $permName }
        if ($role) {
            $resourceAccess += @{ Id = $role.Id; Type = "Role" }
            $found = $true
        }
    }

    if (-not $found) {
        $notFound += $permName
    }
}

if ($notFound.Count -gt 0) {
    Write-Warning "The following permissions were not found as $PermissionType permissions: $($notFound -join ', ')"
    if ($resourceAccess.Count -eq 0) {
        Write-Error "No valid permissions resolved. Aborting."
        exit 1
    }
    $continue = Read-Host "Continue with the permissions that were found? (y/N)"
    if ($continue -ne "y") { exit 0 }
}

# --- Create the app registration ---
Write-Host "Creating app registration '$DisplayName'..." -ForegroundColor Cyan

$appBody = @{
    DisplayName            = $DisplayName
    SignInAudience         = "AzureADMyOrg"
    RequiredResourceAccess = @(
        @{
            ResourceAppId  = $GraphAppId
            ResourceAccess = $resourceAccess
        }
    )
}

$app = New-MgApplication -BodyParameter $appBody

Write-Host "App registration created successfully." -ForegroundColor Green

# --- Create a client secret ---
$secret = Add-MgApplicationPassword -ApplicationId $app.Id -PasswordCredential @{
    DisplayName = "Auto-generated"
    EndDateTime = (Get-Date).AddYears(1)
}

# --- Get tenant ID from current context ---
$context = Get-MgContext
$tenantId = $context.TenantId

# --- Print app data to stdout ---
Write-Host ""
Write-Host "=========== App Registration Data ===========" -ForegroundColor Green
Write-Host "  Tenant ID:       $tenantId"
Write-Host "  Application ID:  $($app.AppId)"
Write-Host "  Client Secret:   $($secret.SecretText)"
Write-Host "==============================================" -ForegroundColor Green
Write-Host ""
Write-Host "  Display Name:    $($app.DisplayName)"
Write-Host "  Object ID:       $($app.Id)"
Write-Host "  Permissions:     $($requestedPerms -join ', ') ($PermissionType)"
Write-Host "  Secret Expires:  $($secret.EndDateTime)"
Write-Host ""
Write-Host "NOTE: Save the Client Secret now - it cannot be retrieved again." -ForegroundColor Yellow
if ($PermissionType -eq "Application") {
    Write-Host "NOTE: Application permissions require admin consent in the Azure portal." -ForegroundColor Cyan
    Write-Host "  Portal link: https://portal.azure.com/#view/Microsoft_AAD_RegisteredApps/ApplicationMenuBlade/~/CallAnAPI/appId/$($app.AppId)" -ForegroundColor Cyan
}

Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null

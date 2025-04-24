<#
.SYNOPSIS
    Tests whether RC4 encryption is enabled in an Active Directory environment.

.DESCRIPTION
    This script checks if RC4 encryption (considered legacy and insecure) is being used
    for Kerberos authentication in your Active Directory environment. It works by:
    1. Clearing existing Kerberos tickets
    2. Forcing authentication to generate new tickets
    3. Analyzing the tickets for RC4 encryption methods

.PARAMETER None
    This script uses current logged-in credentials

.EXAMPLE
    .\Test-RC4-Encryption.ps1

.NOTES
    Author: W00glin
    Version: 1.0
    Date: April 24, 2025
    
    SECURITY NOTE: RC4 is considered cryptographically weak and should be disabled in 
    production environments. Modern environments should use AES encryption instead.
#>

# Step 1: Clear any existing Kerberos tickets in the cache
# This ensures we start with a clean slate for our test
Write-Host "Step 1: Clearing existing Kerberos tickets from cache..." -ForegroundColor Cyan
klist purge
Write-Host "Ticket cache cleared successfully." -ForegroundColor Green

# Step 2: Get domain information for the current environment
# We use the environment variable USERDNSDOMAIN which contains the DNS domain name
$domain = $env:USERDNSDOMAIN
Write-Host "Step 2: Detected domain: $domain" -ForegroundColor Cyan

# Step 3: Trigger Kerberos authentication by accessing a domain resource
# The NETLOGON share is a standard share available on all domain controllers
# Accessing it forces Windows to request a Kerberos ticket
Write-Host "Step 3: Triggering Kerberos authentication by accessing domain resource..." -ForegroundColor Cyan
$testPath = "\\$domain\NETLOGON"
try {
    # Test-Path will attempt to access the resource, which triggers authentication
    if (Test-Path -Path $testPath -ErrorAction Stop) {
        Write-Host "  Successfully authenticated to $testPath" -ForegroundColor Green
    } else {
        Write-Host "  Path $testPath exists but could not be accessed" -ForegroundColor Yellow
    }
} catch {
    Write-Host "  Could not connect to domain resource: $_" -ForegroundColor Yellow
    Write-Host "  This may be due to permissions issues or the resource not being available" -ForegroundColor Yellow
    Write-Host "  Continuing with ticket analysis regardless..." -ForegroundColor Yellow
}

# Step 4: Retrieve and analyze Kerberos tickets from the cache
Write-Host "Step 4: Analyzing Kerberos tickets for encryption types..." -ForegroundColor Cyan
Write-Host "  Retrieving ticket information using 'klist' command..." -ForegroundColor DarkGray

# The 'klist' command displays all Kerberos tickets in the current session
$tickets = klist
Write-Host "  Retrieved ticket information successfully." -ForegroundColor DarkGray

# Step 5: Display the ticket information for reference
Write-Host "`nCurrent Kerberos Tickets:" -ForegroundColor Cyan
Write-Host "---------------------------------------------------" -ForegroundColor Cyan
$tickets | ForEach-Object { Write-Host $_ }
Write-Host "---------------------------------------------------" -ForegroundColor Cyan

# Step 6: Check for RC4 encryption indicators in the ticket data
# RC4 may be listed as either "RC4-HMAC" or "ARCFOUR-HMAC" in the output
Write-Host "`nStep 6: Checking for RC4 encryption indicators..." -ForegroundColor Cyan
$rc4Detected = $false
$rc4Lines = $tickets | Where-Object { $_ -match "RC4-HMAC" -or $_ -match "ARCFOUR-HMAC" }

if ($rc4Lines) {
    $rc4Detected = $true
    Write-Host "  RC4 encryption detected in the following tickets:" -ForegroundColor Red
    $rc4Lines | ForEach-Object { Write-Host "  - $_" -ForegroundColor Red }
} else {
    Write-Host "  No RC4 encryption detected in any tickets." -ForegroundColor Green
}

# Step 7: Check for AES encryption (the preferred modern method)
$aesDetected = $false
$aesLines = $tickets | Where-Object { $_ -match "AES" }

if ($aesLines) {
    $aesDetected = $true
    Write-Host "`nStep 7: Modern encryption methods detected:" -ForegroundColor Cyan
    $aesLines | ForEach-Object { Write-Host "  - $_" -ForegroundColor Green }
} else {
    Write-Host "`nStep 7: No AES encryption detected. This is unusual in modern environments." -ForegroundColor Yellow
}

# Step 8: Provide a summary of findings
Write-Host "`nSUMMARY OF FINDINGS:" -ForegroundColor Cyan
Write-Host "===========================================" -ForegroundColor Cyan

if ($rc4Detected) {
    Write-Host "RESULT: RC4 encryption is ENABLED in your environment!" -ForegroundColor Red
    Write-Host "RECOMMENDATION: Consider disabling RC4 encryption in your domain for improved security." -ForegroundColor Yellow
    Write-Host "  - This can be done through Group Policy or registry settings." -ForegroundColor Yellow
    Write-Host "  - Specifically, look for the 'Network security: Configure encryption types" -ForegroundColor Yellow
    Write-Host "    allowed for Kerberos' policy setting." -ForegroundColor Yellow
} else {
    Write-Host "RESULT: RC4 encryption appears to be DISABLED in your environment." -ForegroundColor Green
    Write-Host "This is the recommended secure configuration." -ForegroundColor Green
}

if ($aesDetected) {
    Write-Host "`nAES encryption is being used, which is the recommended secure method." -ForegroundColor Green
} else {
    Write-Host "`nWARNING: AES encryption was not detected. Verify your encryption settings." -ForegroundColor Yellow
}

Write-Host "`nTECHNICAL BACKGROUND:" -ForegroundColor Cyan
Write-Host "RC4 is a stream cipher that has been proven vulnerable to various attacks." -ForegroundColor DarkGray
Write-Host "Microsoft has been recommending the transition from RC4 to AES since at least 2013." -ForegroundColor DarkGray
Write-Host "AES encryption provides significantly better security for Kerberos authentication." -ForegroundColor DarkGray
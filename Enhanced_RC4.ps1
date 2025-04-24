<#
.SYNOPSIS
    Comprehensive RC4 Encryption Detection Script for Active Directory Environments

.DESCRIPTION
    This script performs a thorough analysis to detect if RC4 encryption (considered insecure)
    is enabled in an Active Directory environment. It uses multiple detection methods:
    1. Checks local security policy settings
    2. Examines registry keys related to Kerberos encryption
    3. Analyzes actual Kerberos tickets obtained during authentication
    4. Considers the context of the executing account (admin vs. regular user)

    RC4 is a legacy encryption algorithm that is considered cryptographically weak and
    should be disabled in modern, secure environments in favor of AES encryption.

.NOTES
    File Name      : Detect-RC4-Encryption.ps1
    Author         : W00glin
    Prerequisite   : PowerShell 3.0 or later
    Version        : 1.0
    Date           : April 24, 2025

    This script does not require the AD PowerShell module and can be run by both
    regular users and administrators. However, the results may vary depending on
    the privileges of the executing account.

.EXAMPLE
    .\Detect-RC4-Encryption.ps1

    Runs the script and provides a comprehensive assessment of RC4 encryption status
    in your current Active Directory environment.
#>

#Requires -Version 3.0

# ----- Script Configuration -----
$ErrorActionPreference = "Continue"  # Continue on errors to complete all checks
$VerbosePreference = "Continue"      # Show verbose output

# ----- Script Variables -----
$ScriptStartTime = Get-Date
$RC4Found = $false
$AESFound = $false

# ----- Begin Main Script -----
Write-Host "Enhanced RC4 Detection Script" -ForegroundColor Cyan
Write-Host "=============================" -ForegroundColor Cyan
Write-Host "Started at: $ScriptStartTime" -ForegroundColor Cyan
Write-Host

# --------------------------------------------------------------------------
# STEP 1: DETECT ACCOUNT TYPE AND ENVIRONMENT
# This section identifies the current user context to understand how it might
# affect the test results. Domain Admin accounts often have different
# security settings and encryption capabilities than regular user accounts.
# --------------------------------------------------------------------------
Write-Host "STEP 1: DETECTING ACCOUNT TYPE AND ENVIRONMENT" -ForegroundColor Cyan
Write-Host "-----------------------------------------------" -ForegroundColor Cyan

# Get current username
$currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
Write-Host "Current user: $currentUser" -ForegroundColor Yellow

# Check if running as local administrator
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator")
Write-Host "Is local administrator: $isAdmin" -ForegroundColor Yellow

# Check if user is a domain admin
$isDomainAdmin = $false
try {
    # The 'whoami /groups' command lists all security groups the current user belongs to
    $currentGroups = whoami /groups
    # Check if the output contains either "Domain Admins" or "Enterprise Admins"
    if ($currentGroups -match "Domain Admins" -or $currentGroups -match "Enterprise Admins") {
        $isDomainAdmin = $true
    }
} catch {
    # Continue if whoami fails
    Write-Host "  Could not determine domain group membership: $_" -ForegroundColor Yellow
}
Write-Host "Is domain administrator: $isDomainAdmin" -ForegroundColor Yellow

# Get domain information
$domain = $env:USERDNSDOMAIN
Write-Host "Current domain: $domain" -ForegroundColor Yellow

# --------------------------------------------------------------------------
# STEP 2: CHECK LOCAL SECURITY POLICY FOR RC4 SETTINGS
# Security policies can define which encryption types are supported at the
# system level. This section exports the local security policy and searches
# for Kerberos encryption type settings.
# --------------------------------------------------------------------------
Write-Host "`nSTEP 2: CHECKING LOCAL SECURITY POLICY FOR RC4 SETTINGS" -ForegroundColor Cyan
Write-Host "---------------------------------------------------------" -ForegroundColor Cyan
Write-Host "The security policy may contain settings that explicitly enable or disable RC4."
$securityPolicy = $null

try {
    # Export current security policy to a temporary file using secedit
    # secedit is a command-line tool that manages security policy
    $tempFile = [System.IO.Path]::GetTempFileName()
    Write-Host "  Exporting security policy to temporary file: $tempFile" -ForegroundColor DarkGray
    Start-Process -FilePath "secedit" -ArgumentList "/export /cfg `"$tempFile`" /quiet" -NoNewWindow -Wait
    
    # Read the policy file content
    $securityPolicy = Get-Content -Path $tempFile -Raw
    
    # Clean up the temporary file
    Remove-Item -Path $tempFile -Force
    
    # Look for Kerberos encryption types in the security policy
    # The SupportedEncryptionTypes setting defines allowed Kerberos encryption methods
    if ($securityPolicy -match "SupportedEncryptionTypes") {
        # Extract the numeric value using regular expression
        $match = [regex]::Match($securityPolicy, "SupportedEncryptionTypes\s*=\s*(\d+)")
        if ($match.Success) {
            $encTypes = [int]$match.Groups[1].Value
            Write-Host "  Found Kerberos encryption types setting: $encTypes" -ForegroundColor Green
            
            # Parse the value - it's a bit field where each bit represents a different encryption type
            # The meaning of each bit:
            # 0x01 (1)   = DES-CBC-CRC
            # 0x02 (2)   = DES-CBC-MD5
            # 0x04 (4)   = RC4-HMAC
            # 0x08 (8)   = AES128-CTS-HMAC-SHA1-96
            # 0x10 (16)  = AES256-CTS-HMAC-SHA1-96
            $supportedTypes = @()
            if ($encTypes -band 0x1) { $supportedTypes += "DES-CBC-CRC" }          # Bitwise AND with 1
            if ($encTypes -band 0x2) { $supportedTypes += "DES-CBC-MD5" }          # Bitwise AND with 2
            if ($encTypes -band 0x4) { $supportedTypes += "RC4-HMAC" }             # Bitwise AND with 4
            if ($encTypes -band 0x8) { $supportedTypes += "AES128-CTS-HMAC-SHA1-96" } # Bitwise AND with 8
            if ($encTypes -band 0x10) { $supportedTypes += "AES256-CTS-HMAC-SHA1-96" } # Bitwise AND with 16
            
            Write-Host "  Supported encryption methods: $($supportedTypes -join ', ')" -ForegroundColor Yellow
            
            # Check if RC4 is in the list of supported encryption types
            if ($supportedTypes -contains "RC4-HMAC") {
                Write-Host "  RC4 is ENABLED in local security policy" -ForegroundColor Red
                $RC4Found = $true
            } else {
                Write-Host "  RC4 is DISABLED in local security policy" -ForegroundColor Green
            }
        } else {
            Write-Host "  Could not parse encryption types value" -ForegroundColor Yellow
        }
    } else {
        Write-Host "  No explicit encryption types setting found in local policy" -ForegroundColor Yellow
        Write-Host "  This typically means the domain default or Windows default is used" -ForegroundColor Yellow
    }
} catch {
    Write-Host "  Error accessing security policy: $_" -ForegroundColor Red
}

# --------------------------------------------------------------------------
# STEP 3: CHECK REGISTRY FOR RC4 SETTINGS
# The Windows registry contains settings that control Kerberos behavior.
# This section checks specific registry keys to determine if RC4 is enabled.
# --------------------------------------------------------------------------
Write-Host "`nSTEP 3: CHECKING REGISTRY FOR RC4 SETTINGS" -ForegroundColor Cyan
Write-Host "----------------------------------------" -ForegroundColor Cyan
Write-Host "Windows stores Kerberos encryption settings in the registry."
try {
    # This registry path contains Kerberos configuration settings
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters"
    Write-Host "  Checking registry path: $regPath" -ForegroundColor DarkGray
    
    # Look for the SupportedEncryptionTypes value
    $regValue = Get-ItemProperty -Path $regPath -Name "SupportedEncryptionTypes" -ErrorAction SilentlyContinue
    
    if ($regValue) {
        $encTypes = $regValue.SupportedEncryptionTypes
        Write-Host "  Found registry setting: $encTypes" -ForegroundColor Green
        
        # Parse the value - it's a bit field (same as in Step 2)
        $supportedTypes = @()
        if ($encTypes -band 0x1) { $supportedTypes += "DES-CBC-CRC" }
        if ($encTypes -band 0x2) { $supportedTypes += "DES-CBC-MD5" }
        if ($encTypes -band 0x4) { $supportedTypes += "RC4-HMAC" }
        if ($encTypes -band 0x8) { $supportedTypes += "AES128-CTS-HMAC-SHA1-96" }
        if ($encTypes -band 0x10) { $supportedTypes += "AES256-CTS-HMAC-SHA1-96" }
        
        Write-Host "  Supported encryption methods: $($supportedTypes -join ', ')" -ForegroundColor Yellow
        
        # Check if RC4 is in the list
        if ($supportedTypes -contains "RC4-HMAC") {
            Write-Host "  RC4 is ENABLED in registry settings" -ForegroundColor Red
            $RC4Found = $true
        } else {
            Write-Host "  RC4 is DISABLED in registry settings" -ForegroundColor Green
        }
    } else {
        Write-Host "  No registry setting found for SupportedEncryptionTypes" -ForegroundColor Yellow
        Write-Host "  This typically means the default Windows settings apply" -ForegroundColor Yellow
        Write-Host "  On modern Windows systems, this usually includes RC4 but prefers AES" -ForegroundColor Yellow
    }
} catch {
    Write-Host "  Error checking registry: $_" -ForegroundColor Red
}

# --------------------------------------------------------------------------
# STEP 4: CHECK ACTUAL KERBEROS TICKETS
# The most reliable way to detect RC4 usage is to check actual Kerberos tickets.
# This section clears existing tickets, forces authentication, and analyzes
# the encryption types used in the newly acquired tickets.
# --------------------------------------------------------------------------
Write-Host "`nSTEP 4: CHECKING ACTUAL KERBEROS TICKETS" -ForegroundColor Cyan
Write-Host "------------------------------------" -ForegroundColor Cyan
Write-Host "Analyzing actual Kerberos tickets provides the most accurate detection of RC4 usage."

# Clear existing tickets from cache
Write-Host "  Clearing existing Kerberos tickets..." -ForegroundColor Yellow
klist purge | Out-Null
Write-Host "  Ticket cache cleared" -ForegroundColor DarkGray

# Force Kerberos ticket acquisition by accessing a domain resource
# NETLOGON is a standard share available on all domain controllers
Write-Host "  Forcing Kerberos ticket acquisition..." -ForegroundColor Yellow
$testPath = "\\$domain\NETLOGON"
try {
    # Attempting to access the path will trigger Kerberos authentication
    Test-Path -Path $testPath -ErrorAction SilentlyContinue | Out-Null
    Write-Host "  Successfully authenticated to domain resource" -ForegroundColor Green
} catch {
    Write-Host "  Could not authenticate to domain resource: $_" -ForegroundColor Yellow
    Write-Host "  This may affect the reliability of the test" -ForegroundColor Yellow
}

# Analyze the tickets with klist command
Write-Host "  Analyzing Kerberos tickets:" -ForegroundColor Yellow
$tickets = klist
$ticketCount = 0

# Display tickets and look for encryption types
foreach ($line in $tickets) {
    # Output each line of the klist result
    Write-Host "    $line" -ForegroundColor DarkGray
    
    # Count tickets for statistics
    if ($line -match "Client:") {
        $ticketCount++
    }
    
    # Check for RC4 encryption indicators
    if ($line -match "RC4-HMAC" -or $line -match "ARCFOUR-HMAC") {
        $RC4Found = $true
        Write-Host "    RC4 ENCRYPTION DETECTED: $line" -ForegroundColor Red
    }
    
    # Check for AES encryption indicators
    if ($line -match "AES") {
        $AESFound = $true
        Write-Host "    AES ENCRYPTION DETECTED: $line" -ForegroundColor Green
    }
}

# Summary of ticket analysis
Write-Host "  Total tickets analyzed: $ticketCount" -ForegroundColor Yellow
if (-not $RC4Found -and -not $AESFound) {
    Write-Host "    No specific encryption types identified in tickets" -ForegroundColor Yellow
    Write-Host "    This could indicate ticket parsing issues or unusual encryption" -ForegroundColor Yellow
}

# --------------------------------------------------------------------------
# STEP 5: ACCOUNT-SPECIFIC CONSIDERATIONS
# Different account types may use different encryption methods. This section
# provides context about how the current account might affect the results.
# --------------------------------------------------------------------------
Write-Host "`nSTEP 5: ACCOUNT-SPECIFIC CONSIDERATIONS" -ForegroundColor Cyan
Write-Host "---------------------------------------" -ForegroundColor Cyan

if ($isDomainAdmin) {
    Write-Host "  You are using a Domain Admin account, which may have different encryption settings" -ForegroundColor Yellow
    Write-Host "  Domain Admin accounts often use stronger encryption by default" -ForegroundColor Yellow
    Write-Host "  For a complete assessment, consider testing with a regular user account as well" -ForegroundColor Yellow
} else {
    Write-Host "  You are using a regular user account, which gives a good representation of" -ForegroundColor Yellow
    Write-Host "  typical encryption usage in your environment" -ForegroundColor Yellow
}

if ($isAdmin -and -not $isDomainAdmin) {
    Write-Host "  Note: You have local administrator rights but not domain admin rights" -ForegroundColor Yellow
    Write-Host "  This should not significantly affect the test results" -ForegroundColor Yellow
}

# --------------------------------------------------------------------------
# STEP 6: OVERALL ASSESSMENT
# This section provides a comprehensive summary of the findings and
# recommendations for improving security if RC4 is detected.
# --------------------------------------------------------------------------
Write-Host "`nSTEP 6: OVERALL ASSESSMENT" -ForegroundColor Cyan
Write-Host "-------------------------" -ForegroundColor Cyan

# End time calculation
$ScriptEndTime = Get-Date
$duration = $ScriptEndTime - $ScriptStartTime
Write-Host "Assessment completed at: $ScriptEndTime" -ForegroundColor DarkGray
Write-Host "Total assessment time: $($duration.TotalSeconds) seconds" -ForegroundColor DarkGray
Write-Host

# Overall RC4 assessment
if ($RC4Found) {
    Write-Host "CONCLUSION: RC4 encryption WAS DETECTED in your environment!" -ForegroundColor Red
    Write-Host "This suggests RC4 is still enabled, which is a security concern." -ForegroundColor Red
    Write-Host
    Write-Host "SECURITY IMPLICATIONS:" -ForegroundColor Red
    Write-Host "- RC4 is considered cryptographically weak and vulnerable to attacks" -ForegroundColor Red
    Write-Host "- It no longer meets modern security standards for protecting authentication" -ForegroundColor Red
    Write-Host "- RC4 usage might indicate legacy compatibility requirements in your environment" -ForegroundColor Red
} else {
    Write-Host "CONCLUSION: RC4 encryption was NOT DETECTED in your current session." -ForegroundColor Green
    Write-Host "This suggests RC4 may be disabled, which is the secure configuration." -ForegroundColor Green
    Write-Host
    Write-Host "SECURITY BENEFITS:" -ForegroundColor Green
    Write-Host "- Your environment appears to use modern encryption algorithms" -ForegroundColor Green
    Write-Host "- This reduces the risk of Kerberos tickets being compromised" -ForegroundColor Green
    Write-Host "- AES encryption provides significantly stronger security than RC4" -ForegroundColor Green
}

# Account-specific notes
if ($isDomainAdmin) {
    Write-Host "`nIMPORTANT NOTE:" -ForegroundColor Yellow
    Write-Host "Your Domain Admin status may affect these results." -ForegroundColor Yellow
    Write-Host "For a comprehensive assessment, run this test with both admin and non-admin accounts." -ForegroundColor Yellow
}

# Detected encryption methods
Write-Host "`nDETECTED ENCRYPTION METHODS:" -ForegroundColor Cyan
Write-Host "- RC4 encryption: " -NoNewline
if ($RC4Found) {
    Write-Host "Detected" -ForegroundColor Red
} else {
    Write-Host "Not detected" -ForegroundColor Green
}

Write-Host "- AES encryption: " -NoNewline
if ($AESFound) {
    Write-Host "Detected" -ForegroundColor Green
} else {
    Write-Host "Not detected (unusual in modern environments)" -ForegroundColor Yellow
}

# Recommendations section
Write-Host "`nRECOMMENDATIONS:" -ForegroundColor Cyan
if ($RC4Found) {
    Write-Host "To fully disable RC4 in your domain:" -ForegroundColor Yellow
    Write-Host "1. Configure Group Policy:" -ForegroundColor Yellow
    Write-Host "   Computer Configuration → Policies → Windows Settings → Security Settings" -ForegroundColor DarkGray
    Write-Host "   → Local Policies → Security Options → Network security: Configure encryption types" -ForegroundColor DarkGray
    Write-Host "   allowed for Kerberos → Enable only AES encryption types" -ForegroundColor DarkGray
    Write-Host "2. Apply the following registry setting to disable RC4:" -ForegroundColor Yellow
    Write-Host "   Registry Path: HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters" -ForegroundColor DarkGray
    Write-Host "   Value Name: SupportedEncryptionTypes" -ForegroundColor DarkGray
    Write-Host "   Value Type: DWORD" -ForegroundColor DarkGray
    Write-Host "   Value Data: 24 (decimal) - Enables only AES128 and AES256" -ForegroundColor DarkGray
    Write-Host "3. Identify and update any legacy applications that might require RC4" -ForegroundColor Yellow
    Write-Host "4. Test thoroughly in a non-production environment before implementing" -ForegroundColor Yellow
    Write-Host "   in production to avoid authentication failures" -ForegroundColor Yellow
} else {
    Write-Host "Your environment appears to be properly configured with secure encryption." -ForegroundColor Green
    Write-Host "Maintain current security practices and regularly audit for changes." -ForegroundColor Green
}

# Technical references
Write-Host "`nTECHNICAL REFERENCES:" -ForegroundColor Cyan
Write-Host "1. Microsoft Security Advisory on RC4: https://technet.microsoft.com/library/security/2868725" -ForegroundColor DarkGray
Write-Host "2. Encryption Type Values: https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/network-security-configure-encryption-types-allowed-for-kerberos" -ForegroundColor DarkGray
Write-Host "3. Best Practices for Kerberos Encryption: https://docs.microsoft.com/en-us/windows-server/security/kerberos/kerberos-authentication-overview" -ForegroundColor DarkGray

Write-Host "`nScript execution completed." -ForegroundColor Cyan
<#
Script to create local account with random password and put the user in Administrator group.
The script uses MgGraph with Client secret to put the device into a specific group, so Cloud Laps policy can be enabled on a specific group.
Api permissions needed for app registration:
Directory.readwrite.all
GroupMember.ReadWrite.all

please insert relevant information on these lines:

Line 47 - Set username for your account
Line 96 - Client ID from app registration
Line 97 - Tenant ID
Line 98 - Client Secret value from app registration
Line 111 - Group object iD that the machine should be put in after User added 

#>

Set-ExecutionPolicy Bypass -scope Process -Force

Install-Module -Name Microsoft.Graph.Groups -Confirm:$false -Force:$true
Install-Module -Name Microsoft.Graph.Identity.DirectoryManagement -Confirm:$false -Force:$true

function Generate-RandomPassword {
    param (
        [Parameter(Mandatory)]
        [int] $length
    )
 
    $charSet = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'.ToCharArray()
 
    $rng = New-Object System.Security.Cryptography.RNGCryptoServiceProvider
    $bytes = New-Object byte[]($length)
  
    $rng.GetBytes($bytes)
  
    $result = New-Object char[]($length)
  
    for ($i = 0 ; $i -lt $length ; $i++) {
        $result[$i] = $charSet[$bytes[$i]%$charSet.Length]
    }
 
    return -join $result
}
 
$createpassword = Generate-RandomPassword 14

$username = "support"   # Administrator is built-in name
$password = ConvertTo-SecureString $createpassword -AsPlainText -Force
$logFile = "c:\temp\$username.txt"

Function Write-Log {
  param(
      [Parameter(Mandatory = $true)][string] $message,
      [Parameter(Mandatory = $false)]
      [ValidateSet("INFO","WARN","ERROR")]
      [string] $level = "INFO"
  )
  # Create timestamp
  $timestamp = (Get-Date).toString("yyyy/MM/dd HH:mm:ss")

  # Append content to log file
  Add-Content -Path $logFile -Value "$timestamp [$level] - $message"
}

Function Create-LocalAdmin {
    process {
      try {
        New-LocalUser "$username" -Password $password -FullName "$username" -Description "local support admin" -ErrorAction stop
        Write-Log -message "$username local user crated"

        # Add new user to administrator group
        Add-LocalGroupMember -Group "Administrators" -Member "$username" -ErrorAction stop
        Write-Log -message "$username added to the local administrator group"
      }catch{
        Write-log -message "Creating local account failed" -level "ERROR"
      }
    }    
}

Write-Log -message "#########"
Write-Log -message "$env:COMPUTERNAME - Create local admin account"

Create-LocalAdmin

Write-Log -message "#########"

$SEL = Select-String -Path $logFile -Pattern "$username added to the local administrator group"

if ($SEL -ne $null)
{
    
Import-Module -Name Microsoft.Graph.Groups
Import-Module -Name Microsoft.Graph.Identity.DirectoryManagement

    # Configuration
$ClientId = "XXXXXX"
$TenantId = "XXXXXXXXXX"
$ClientSecret = "XXXXXXXXX"

# Convert the client secret to a secure string
$ClientSecretPass = ConvertTo-SecureString -String $ClientSecret -AsPlainText -Force

# Create a credential object using the client ID and secure string
$ClientSecretCredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $ClientId, $ClientSecretPass

# Connect to Microsoft Graph with Client Secret
Connect-MgGraph -TenantId $tenantId -ClientSecretCredential $ClientSecretCredential

$devices = Get-MgDevice -Filter "displayName eq '$env:COMPUTERNAME'" | select -ExpandProperty "Id"
foreach ($ObjectId in $devices) {
    New-MgGroupMember -GroupId "XXXXXXXXXXXXX" -DirectoryObjectId "$ObjectId"
}

}
else
{
    Exit 1
}

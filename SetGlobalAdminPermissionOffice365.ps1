<#
.SYNOPSIS
    SetGlobalAdminPermissionOffice365.ps1
.DESCRIPTION
    This script add the Global Admin permission to a specific user and Tenant
    All the process is done thought CSP credential (impersonating customers login).
    It helps the CSP Administrator to set permissions in customer tenants
.PARAMETER TenantLogin
    Customer login that is registered in CSP Portal
.PARAMETER TenantAdminUser
    This is the account name that will be granted as Global administrator
.PARAMETER Office365CPSAdministratorCredential
    You have to insert the CSP credential before run the process.
    It must be a CSP Administrator

.EXAMPLE
    C:\PS> 
     SetGlobalAdminPermissionOffice365.ps1 -TenantLogin academiadooffice -TenantAdminUser contato@corp360.com.br -Office365CPSAdministratorCredential (Get-Credential)
.NOTES
    Author: Fabrizio Zavalloni
    Date:   October 09, 2017  
    
#>

param(
    [Parameter(Mandatory=$true, Position=0)][ValidateNotNullOrEmpty()] $TenantLogin,
    [Parameter(Mandatory=$true, Position=1)][ValidateNotNullOrEmpty()] $TenantAdminUser,
    [Parameter(Mandatory=$true, Position=2)][System.Management.Automation.CredentialAttribute()] $Office365CPSAdministratorCredential
    )

#Conect in Office 365 CSP
Import-Module MSOnline

Connect-MsolService -Credential $Office365CPSAdministratorCredential -ErrorAction SilentlyContinue -ErrorVariable outputError

if($outputError)
{    
	write-error "Error on connecting Office 365: $_"
    exit 
}

#Create a list of All tenants a login contains
#The same customer can have more than 1 tenants
$loginTenantsList = Get-MsolPartnerContract -All | Select * | where-object{$_.Name -eq $TenantLogin}

#Check all tenants seaching for the tenantGlobalAdminUser to add the permission
foreach($tenant in $loginTenantsList)
{
    $tenantUsers = Get-MsolUser -TenantId $tenant.TenantId

    foreach($user in $tenantUsers)
    {        
        if($user.UserPrincipalName -eq $TenantAdminUser)
        {
            Write-Host "User found: " $user.UserPrincipalName

            Add-MsolRoleMember -TenantId $tenant.TenantId -RoleMemberEmailAddress $user.UserPrincipalName -RoleName "Company Administrator" -ErrorVariable outputErrorPermissionCMD -EA SilentlyContinue

            if($outputErrorPermissionCMD)
            {
                Write-Error "Error: $outputErrorPermissionCMD"
            }
            else
            {
                Write-Host "Global Admin Permission Added successfully"
            }
            
            break;
        } 

    }
}

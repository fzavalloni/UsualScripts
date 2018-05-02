<#
.SYNOPSIS
    check_imap_emailconnector.ps1
.DESCRIPTION
    This script is a Nagios monitors that checks the IMAP mailboxes connectivity and check the processed messages

    It can also be used to purge all the Inbox messages, but use it carefully.

.PARAMETER Server (MANDATORY)
    Imap Server Host/IP

.PARAMETER User (MANDATORY)
    Imap username

.PARAMETER Password (MANDATORY)
    Imap Password

.PARAMETER Folder (OPTIONAL)
    Folder to be monitored. Default: Inbox

.PARAMETER Ssl (Boolean) (OPTIONAL)
    IMAPS or IMAP. Default: true

.PARAMETER Port (OPTIONAL)
    Imap port. Default: 993

.PARAMETER ImapLibraryPath (OPTIONAL)
    Imap LibraryPath. Only Mailkit supported 
    Default: C:\Libraries\MailKit.dll

.PARAMETER Purge (OPTIONAL)
    Delete all foder messages **CAUTION**
    Default: $false

.PARAMETER SuccessThreshold (OPTIONAL)
    Nagios Success Threshould
    Default: 5

.PARAMETER FailureThreshold (OPTIONAL)
    Nagios Failure Threshould
    Default: 15

.EXAMPLES
    C:\PS> 
     check_imap_emailconnector.ps1 -Server Imap.Domain.com -User user@domain.com -Password Secret1234

    C:\PS> 
     check_imap_emailconnector.ps1 -Server Imap.Domain.com -User user@domain.com -Password Secret1234 -Purge $true

.NOTES
    Author: Fabrizio Zavalloni
    Date:   Abril 26, 2018
    Email:  fzavalloni@hotmail.com   
#>
param(
    [Parameter(Mandatory=$true)][string] $Server,
    [Parameter(Mandatory=$true)][string] $User,
    [Parameter(Mandatory=$true)][string] $Password,
    [Parameter(Mandatory=$false)][string] $FolderName = 'INBOX',
    [Parameter(Mandatory=$false)][bool] $Ssl = $true,
    [Parameter(Mandatory=$false)][int] $Port = 993,
    [Parameter(Mandatory=$false)][string] $ImapLibraryPath = "C:\Libraries\MailKit.dll",
    [Parameter(Mandatory=$false)][bool] $Purge = $false,
    [Parameter(Mandatory=$false)][int] $FailureThreshold = 15 ,
    [Parameter(Mandatory=$false)][int] $SuccessThreshold = 5
)

# Nagios outputs
function FailureOutput($message)
{
   Write-Host "FAILURE: $($message)"
   [System.Environment]::Exit(2)
}

function WarningOutput($message)
{
    Write-Host "WARNING: $($message)"
    [System.Environment]::Exit(1)
}

function SuccessOutput($message)
{
    Write-Host "OK: $($message)"
    [System.Environment]::Exit(0)
}

# Adding Assemblies
Try
{
    Add-Type -Path $ImapLibraryPath
    $client = New-Object MailKit.Net.Imap.ImapClient
    $token = New-Object System.Threading.CancellationTokenSource
    $cancellationToken = ($token.Token)
    
}
catch
{
    FailureOutput $_.Exception.Message
}

Try
{
    if($ssl)
    {
        $sslOptions = [MailKit.Security.SecureSocketOptions]::SslOnConnect
    }
    else
    {
        $sslOptions = [MailKit.Security.SecureSocketOptions]::None
    }

    # Bypass SSL validation
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }

    try
    {
        $client.Connect($Server,$Port,$sslOptions,$cancellationToken)
        $client.Authenticate($User,$Password,$cancellationToken)
    }
    catch
    {
        FailureOutput $_.Exception.Message 
    }
    
    $folder = $client.GetFolder($FolderName,$cancellationToken)

    if($folder.Exists)
    {
        $openFolder = $Folder.Open([MailKit.FolderAccess]::ReadWrite,$cancellationToken)
        $msgSearch = $Folder.Search([MailKit.Search.SearchOptions]::All,[MailKit.Search.SearchQuery]::All,$cancellationToken)

        #Purge messages
        if($Purge)
        { 
            #Confirmation prompt
            $title = "Imap Messages Purge"
            $message = "Are you sure to DELETE all IMAP messages?"
            $yes = New-Object System.Management.Automation.Host.ChoiceDescription "&Yes", "Purge all messages"
            $no = New-Object System.Management.Automation.Host.ChoiceDescription "&No", "Exit."
            $options = [System.Management.Automation.Host.ChoiceDescription[]]($yes, $no)
            $result = $host.ui.PromptForChoice($title, $message, $options, 1)

            switch($result)
            {   
               0 { 
                    # Mark to deletion and purging               
                    foreach($msg in $msgSearch.UniqueIds)
                    {
                        [MailKit.UniqueId]$id = $msg.Id
                        $folder.AddFlags($id,[MailKit.MessageFlags]::Deleted,$true,$cancellationToken)                                     
                    }
                    $Folder.Expunge($msgSearch.UniqueIds,$cancellationToken)
                    Write-Host "$($msgSearch.Count) messages have been purged"
                    exit
                }
                1 {
                    Write-Host "Exiting..."
                    exit                        
                }
            }                                 
        }  
        
        # Nagios validation
        [int]$messageCount = $msgSearch.Count

        if($messageCount -le $SuccessThreshold)
        {
            SuccessOutput "Authenticated and $($messageCount) pending to process"
        }
        elseif($messageCount -In $SuccessThreshold..$FailureThreshold)
        {
            WarningOutput "Authenticated and $($messageCount) pending to process"
        }
        else
        {
            FailureOutput "Authenticated and $($messageCount) pending to process"
        }
    }
    else
    {
        FailureOutput "Folder not found"
    }
    
}
catch
{
    FailureOutput $_.Exception.Message
}
finally
{
    $client.Dispose()
}
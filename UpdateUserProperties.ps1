# Script UpdateUserProperties
<# .SYNOPSIS
     Script updates Active Directory Properties
.DESCRIPTION
     It was built to update all Active Directory Properties based on a CSV file
     Example of file format

     Name;Login;Email;Phone;Mobile;Department;CC;BusinessUnit
     Bruno Campestri;bruno.campestri;bruno.campestri@uol.com.br;11 555-0444 R: 845;11 98562-8547;Business;L3272;Contoso

     Parameters:

     -ImportFilePath - Path of CSV file
     -CreateLog - Create a log file, it is created in the current directory

     Examples:

     .\UpdateUserProperties.ps1 -ImportFilePath "E:\Users.csv" -CreateLog

.NOTES
     Author     : Fabrizio Zavalloni - fzavalloni@hotmail.com
.LINK
     http://github.com/fzavalloni
#>


param(
[parameter(Mandatory=$true)]
[ValidateNotNullOrEmpty()]
[string]
$ImportFilePath,
[switch]$CreateLog

)

$logPath = ".\UpdateUserProperties.log"

#Functions

function Write-Log 
{ 
    [CmdletBinding()] 
    Param 
    ( 
        [Parameter(Mandatory=$true, 
                   ValueFromPipelineByPropertyName=$true)] 
        [ValidateNotNullOrEmpty()] 
        [Alias("LogContent")] 
        [string]$Message, 
 
        [Parameter(Mandatory=$true)] 
        [Alias('LogPath')] 
        [string]$Path, 
         
        [Parameter(Mandatory=$true)] 
        [ValidateSet("Error","Warn","Info")] 
        [string]$Level, 
         
        [Parameter(Mandatory=$false)] 
        [switch]$NoClobber 
    ) 
 
    Begin 
    { 
        # Set VerbosePreference to Continue so that verbose messages are displayed. 
        $VerbosePreference = 'Continue' 
    } 
    Process 
    { 
         
        # If the file already exists and NoClobber was specified, do not write to the log. 
        if ((Test-Path $Path) -AND $NoClobber) { 
            Write-Error "Log file $Path already exists, and you specified NoClobber. Either delete the file or specify a different name." 
            Return 
            } 
 
        # If attempting to write to a log file in a folder/path that doesn't exist create the file including the path. 
        elseif (!(Test-Path $Path)) { 
            #Write-Verbose "Creating $Path." 
            $NewLogFile = New-Item $Path -Force -ItemType File 
            } 
 
        else { 
            # Nothing to see here yet. 
            } 
 
        # Format Date for our Log File 
        $FormattedDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss" 
 
        # Write message to error, warning, or verbose pipeline and specify $LevelText 
        switch ($Level) { 
            'Error' { 
                #Write-Warning $Message 
                $LevelText = 'ERROR:' 
                } 
            'Warn' { 
                #Write-Warning $Message 
                $LevelText = 'WARNING:' 
                } 
            'Info' { 
                #Write-Verbose $Message 
                $LevelText = 'INFO:' 
                } 
            } 
         
        # Write log entry to $Path 
        "$FormattedDate $LevelText $Message" | Out-File -FilePath $Path -Append 
    } 
    End 
    { 
    } 
}

function CheckIfValueIsNotEmpty($value)
{
    if([string]::IsNullOrEmpty($value))
    {
        return $null
    }
    else
    {
        return $value
    }
}

Import-Module ActiveDirectory

$importedData = Import-Csv -Path $ImportFilePath -Delimiter ";"

foreach($user in $importedData)
{       
    try
    {
       $output = "User: $($user.Name) being precessed"

       if($CreateLog)
       {
           Write-Log -Message $output -Level Info -Path $logPath
       }
        
       Write-Host $output
       
       $login = $user.Login
       $displayName = $user.Name
       $mobile = $user.Mobile
       $cc = $user.CC
       $businessUnit = $user.BusinessUnit
       $department = $user.Department
       $officePhone = $user.Phone

       if([string]::IsNullOrEmpty($login) -or [string]::IsNullOrEmpty($displayName))
       {
            Write-Log -Message "Error: The attributes login or display name cannot be null" -Level Error -Path $logPath            
       }
       else
       {
            #if some of the values are empty, it fills with $null

            $mobile = (CheckIfValueIsNotEmpty $mobile)
            $cc = (CheckIfValueIsNotEmpty $cc)
            $businessUnit = (CheckIfValueIsNotEmpty $businessUnit)
            $department = (CheckIfValueIsNotEmpty $department)
            $officePhone = (CheckIfValueIsNotEmpty $officePhone)            

            Get-ADUser -Identity $login | Set-ADUser -DisplayName $displayName -MobilePhone $mobile -Office $cc -Company $businessUnit -Department $department -OfficePhone $officePhone
       }
        
    }

    catch
    {
       if($CreateLog)
       {
            Write-Log -Message "$_" -Level Error -Path $logPath
       }
        
       Write-Error "$_"
    }      
}


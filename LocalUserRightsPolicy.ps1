<#
.SYNOPSIS
    LocalUserRightsPolicy.ps1
.DESCRIPTION
    This script was created to add/query Local User Rights Policies.
    To check all the grant types that works, check the site below.
    https://msdn.microsoft.com/en-us/library/windows/desktop/bb545671(v=vs.85).aspx

.PARAMETER Action (MANDATORY)
    This parameter can be AddPermission and CheckPermission
.PARAMETER AccessType (MANDATORY)
    This parameter is what type of grant um want to process
.PARAMETER UserName (MANDATORY)
    Ex: Domain\UserName

.EXAMPLE
    C:\PS> 
     LocalUserRightsPolicy.ps1 -Action AddPermission -AccessType SeServiceLogonRight -UserName Domain\UserName
.NOTES
    Author: Fabrizio Zavalloni
    Date:   March 09, 2018
    Email:  fzavalloni@hotmail.com  
#>

param
(
    [Parameter(Mandatory=$true,Position=0)][ValidateSet("AddPermission","CheckPermission")] $Action,
    [Parameter(Mandatory=$true, Position=1)][ValidateSet("SeBatchLogonRight","SeDenyBatchLogonRight","SeDenyInteractiveLogonRight",
        "SeDenyNetworkLogonRight","SeDenyRemoteInteractiveLogonRight","SeDenyServiceLogonRight","SeInteractiveLogonRight","SeNetworkLogonRight",
        "SeRemoteInteractiveLogonRight","SeServiceLogonRight")] $AccessType,
    [Parameter(Mandatory=$true, Position=2)][ValidateNotNullOrEmpty()] $UserName
)

$ErrorActionPreference = "Stop"

#This is a C# code that is used to Add the permssion.
#I've created in this way because is more safe to add the permissions, instead
#of using the scedit.exe tool (making export file /replace text/import file again)
Add-Type @'
using System;
using System.Collections.Generic;
using System.Text;

namespace LSA
{
    using System.Runtime.InteropServices;
    using System.Security;
    using System.Management;
    using System.Runtime.CompilerServices;
    using System.ComponentModel;

    using LSA_HANDLE = IntPtr;

    [StructLayout(LayoutKind.Sequential)]
    struct LSA_OBJECT_ATTRIBUTES
    {
        internal int Length;
        internal IntPtr RootDirectory;
        internal IntPtr ObjectName;
        internal int Attributes;
        internal IntPtr SecurityDescriptor;
        internal IntPtr SecurityQualityOfService;
    }
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct LSA_UNICODE_STRING
    {
        internal ushort Length;
        internal ushort MaximumLength;
        [MarshalAs(UnmanagedType.LPWStr)]
        internal string Buffer;
    }
    sealed class Win32Sec
    {
        [DllImport("advapi32", CharSet = CharSet.Unicode, SetLastError = true),
        SuppressUnmanagedCodeSecurityAttribute]
        internal static extern uint LsaOpenPolicy(
        LSA_UNICODE_STRING[] SystemName,
        ref LSA_OBJECT_ATTRIBUTES ObjectAttributes,
        int AccessMask,
        out IntPtr PolicyHandle
        );

        [DllImport("advapi32", CharSet = CharSet.Unicode, SetLastError = true),
        SuppressUnmanagedCodeSecurityAttribute]
        internal static extern uint LsaAddAccountRights(
        LSA_HANDLE PolicyHandle,
        IntPtr pSID,
        LSA_UNICODE_STRING[] UserRights,
        int CountOfRights
        );

        [DllImport("advapi32", CharSet = CharSet.Unicode, SetLastError = true),
        SuppressUnmanagedCodeSecurityAttribute]
        internal static extern int LsaLookupNames2(
        LSA_HANDLE PolicyHandle,
        uint Flags,
        uint Count,
        LSA_UNICODE_STRING[] Names,
        ref IntPtr ReferencedDomains,
        ref IntPtr Sids
        );

        [DllImport("advapi32")]
        internal static extern int LsaNtStatusToWinError(int NTSTATUS);

        [DllImport("advapi32")]
        internal static extern int LsaClose(IntPtr PolicyHandle);

        [DllImport("advapi32")]
        internal static extern int LsaFreeMemory(IntPtr Buffer);

    }
    /// <summary>
    /// This class is used to grant "Log on as a service", "Log on as a batchjob", "Log on localy" etc.
    /// to a user.
    /// </summary>
    public sealed class LsaWrapper : IDisposable
    {
        [StructLayout(LayoutKind.Sequential)]
        struct LSA_TRUST_INFORMATION
        {
            internal LSA_UNICODE_STRING Name;
            internal IntPtr Sid;
        }
        [StructLayout(LayoutKind.Sequential)]
        struct LSA_TRANSLATED_SID2
        {
            internal SidNameUse Use;
            internal IntPtr Sid;
            internal int DomainIndex;
            uint Flags;
        }

        [StructLayout(LayoutKind.Sequential)]
        struct LSA_REFERENCED_DOMAIN_LIST
        {
            internal uint Entries;
            internal LSA_TRUST_INFORMATION Domains;
        }

        enum SidNameUse : int
        {
            User = 1,
            Group = 2,
            Domain = 3,
            Alias = 4,
            KnownGroup = 5,
            DeletedAccount = 6,
            Invalid = 7,
            Unknown = 8,
            Computer = 9
        }

        enum Access : int
        {
            POLICY_READ = 0x20006,
            POLICY_ALL_ACCESS = 0x00F0FFF,
            POLICY_EXECUTE = 0X20801,
            POLICY_WRITE = 0X207F8
        }
        const uint STATUS_ACCESS_DENIED = 0xc0000022;
        const uint STATUS_INSUFFICIENT_RESOURCES = 0xc000009a;
        const uint STATUS_NO_MEMORY = 0xc0000017;

        IntPtr lsaHandle;

        public LsaWrapper()
            : this(null)
        { }
        // // local system if systemName is null
        public LsaWrapper(string systemName)
        {
            LSA_OBJECT_ATTRIBUTES lsaAttr;
            lsaAttr.RootDirectory = IntPtr.Zero;
            lsaAttr.ObjectName = IntPtr.Zero;
            lsaAttr.Attributes = 0;
            lsaAttr.SecurityDescriptor = IntPtr.Zero;
            lsaAttr.SecurityQualityOfService = IntPtr.Zero;
            lsaAttr.Length = Marshal.SizeOf(typeof(LSA_OBJECT_ATTRIBUTES));
            lsaHandle = IntPtr.Zero;
            LSA_UNICODE_STRING[] system = null;
            if (systemName != null)
            {
                system = new LSA_UNICODE_STRING[1];
                system[0] = InitLsaString(systemName);
            }

            uint ret = Win32Sec.LsaOpenPolicy(system, ref lsaAttr,
            (int)Access.POLICY_ALL_ACCESS, out lsaHandle);
            if (ret == 0)
                return;
            if (ret == STATUS_ACCESS_DENIED)
            {
                throw new UnauthorizedAccessException();
            }
            if ((ret == STATUS_INSUFFICIENT_RESOURCES) || (ret == STATUS_NO_MEMORY))
            {
                throw new OutOfMemoryException();
            }
            throw new Win32Exception(Win32Sec.LsaNtStatusToWinError((int)ret));
        }

        public void AddPrivileges(string account, string privilege)
        {
            IntPtr pSid = GetSIDInformation(account);
            LSA_UNICODE_STRING[] privileges = new LSA_UNICODE_STRING[1];
            privileges[0] = InitLsaString(privilege);
            uint ret = Win32Sec.LsaAddAccountRights(lsaHandle, pSid, privileges, 1);
            if (ret == 0)
                return;
            if (ret == STATUS_ACCESS_DENIED)
            {
                throw new UnauthorizedAccessException();
            }
            if ((ret == STATUS_INSUFFICIENT_RESOURCES) || (ret == STATUS_NO_MEMORY))
            {
                throw new OutOfMemoryException();
            }
            throw new Win32Exception(Win32Sec.LsaNtStatusToWinError((int)ret));
        }

        public void Dispose()
        {
            if (lsaHandle != IntPtr.Zero)
            {
                Win32Sec.LsaClose(lsaHandle);
                lsaHandle = IntPtr.Zero;
            }
            GC.SuppressFinalize(this);
        }
        ~LsaWrapper()
        {
            Dispose();
        }
        // helper functions

        IntPtr GetSIDInformation(string account)
        {
            LSA_UNICODE_STRING[] names = new LSA_UNICODE_STRING[1];
            LSA_TRANSLATED_SID2 lts;
            IntPtr tsids = IntPtr.Zero;
            IntPtr tdom = IntPtr.Zero;
            names[0] = InitLsaString(account);
            lts.Sid = IntPtr.Zero;            
            int ret = Win32Sec.LsaLookupNames2(lsaHandle, 0, 1, names, ref tdom, ref tsids);
            if (ret != 0)
                throw new Win32Exception(Win32Sec.LsaNtStatusToWinError(ret));
            lts = (LSA_TRANSLATED_SID2)Marshal.PtrToStructure(tsids,
            typeof(LSA_TRANSLATED_SID2));
            Win32Sec.LsaFreeMemory(tsids);
            Win32Sec.LsaFreeMemory(tdom);
            return lts.Sid;
        }

        static LSA_UNICODE_STRING InitLsaString(string s)
        {
            // Unicode strings max. 32KB
            if (s.Length > 0x7ffe)
                throw new ArgumentException("String too long");
            LSA_UNICODE_STRING lus = new LSA_UNICODE_STRING();
            lus.Buffer = s;
            lus.Length = (ushort)(s.Length * sizeof(char));
            lus.MaximumLength = (ushort)(lus.Length + sizeof(char));
            return lus;
        }
    }
    public class Manager
    {
        public static void AddPrivileges(string account, string privilege)
        {
            using (LsaWrapper lsaWrapper = new LsaWrapper())
            {
                lsaWrapper.AddPrivileges(account, privilege);
            }
        }        
    }    
}
'@ -ErrorAction SilentlyContinue

#Function that checks if the permission is already in place.
#Ps: I tried to get this information using C#, but I couldn't

function IsAlreadyAddedPermission{
param(
    [string] $user,
    [string] $access
    )
    
    $tempFilePath = "{0}\temp\export.inf" -f $env:SYSTEMROOT

    $returnValue = $false
    #Get list of currently used SIDs 
    secedit /export /cfg $tempFilePath | Out-Null
    $curSIDs = Select-String $tempFilePath -Pattern "$($access)"
    $Sids = $curSIDs.line 
    
    try
    {
        $objUser = New-Object System.Security.Principal.NTAccount($user)
        $strSID = $objUser.Translate([System.Security.Principal.SecurityIdentifier])
    }
    catch
    {
        Write-Error "Check if the username: $($user) exits"
    }
    
    #Check if the SID user is listed
    if($Sids.Contains($strSID))
    {        
        $returnValue = $true
    }
 
    
    del $tempFilePath -force -ErrorAction SilentlyContinue   

    return $returnValue

}

function OutputTable($userName,$isAccess)
{
    $table = New-Object system.Data.DataTable “OutPutTable”

    $col1 = New-Object system.Data.DataColumn UserName,([string])
    $col2 = New-Object system.Data.DataColumn IsAccessAlreadyAdded,([bool])

    $table.columns.add($col1)
    $table.columns.add($col2)

    $row = $table.NewRow()

    $row.UserName = $userName 
    $row.IsAccessAlreadyAdded = $isAccess 
    
    $table.Rows.Add($row)

    #Show the Output
    $table
}


try
{

    if([String]::Equals($Action,"AddPermission",[StringComparison]::CurrentCultureIgnoreCase))
    {    
        [LSA.Manager]::AddPrivileges($UserName, $AccessType)
        Write-Host "Permission added successfully!"          
    }
    else 
    {        
        $result = IsAlreadyAddedPermission $UserName $AccessType    
        OutputTable $UserName $result
    }
}
catch{}
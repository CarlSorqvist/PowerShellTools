using namespace System
using namespace System.DirectoryServices
using namespace System.DirectoryServices.Protocols
using namespace System.Security
using namespace System.Security.Principal

Add-Type -AssemblyName System.DirectoryServices.Protocols -ErrorAction Stop

$Id = [LdapDirectoryIdentifier]::new("", 389, $false, $false)
$Ldap = [LdapConnection]::new($Id, $null, [AuthType]::Negotiate)
$Ldap.SessionOptions.ProtocolVersion = 3
$Ldap.SessionOptions.Sealing = $true
$Ldap.SessionOptions.Signing = $true
$Ldap.Bind()

$SdOwnerControl = [SecurityDescriptorFlagControl]::new([Protocols.SecurityMasks]::Owner)
$SdOwnerAndDaclControl = [SecurityDescriptorFlagControl]::new([Protocols.SecurityMasks]::Owner -bor [Protocols.SecurityMasks]::Dacl)

$Dn = "CN=Copy of Computer Test,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=corp,DC=contoso,DC=com"
$Attr = "nTSecurityDescriptor"

<# 

We need SeTakeOwnershipPrivilege and SeRestorePrivilege on DCs to 1) take ownership and 2) set the owner to Enterprise Admins.

If we can read the SD of the object, we can check the current owner, and only take ownership and update it if necessary. On the other hand, if we can't read the SD, we need to take ownership first - but to ensure that we don't
have to do it again in the future, we also add Authenticated Users with Read rights to the object. This way, we can easily check the owner next time without taking ownership again.

#>

# Get current user identity
$CurrentUser = [WindowsIdentity]::GetCurrent().User

# Get the SID of Enterprise Admins. Since 1) the group can be renamed, 2) the PDC operating system may have been installed in a language other then English,
# and 3) we may be in a child domain in a multidomain forest, we need to find the root domain, get its SID, and combine it with the WellKnownSid for Enterprise Admins.
# Of course, this entire section can be replaced with the hardcoded SID of Enterprise Admins if so desired.

# Get RootDSE
$RootDNCAttr = "rootDomainNamingContext"
$RootDse = [SearchResponse]$Ldap.SendRequest([SearchRequest]::new("", "(&(objectClass=*))", [Protocols.SearchScope]::Base, $RootDNCAttr))
$RootDomain = $RootDse.Entries[0].Attributes[$RootDNCAttr][0].ToString()

# Next, connect to GC and find the domainDNS object with the distinguished name of the root domain
$GC = [LdapConnection]::new([LdapDirectoryIdentifier]::new("", 3268, $false, $false))
$GC.Bind()

$RootDomainEntry = [SearchResponse]$GC.SendRequest([SearchRequest]::new($RootDomain, "(&(objectClass=domainDNS))", [Protocols.SearchScope]::Base, "objectSID"))
$BinarySid = $RootDomainEntry.Entries[0].Attributes["objectSID"][0]
$RootDomainSid = [SecurityIdentifier]::new($BinarySid, 0)
$GC.Dispose()

# Now that we have the root domain SID, create the SID for Enterprise Admins
$EnterpriseAdminsSid = [SecurityIdentifier]::new([WellKnownSidType]::AccountEnterpriseAdminsSid, $RootDomainSid)

# Get the principal for Authenticated Users
$AuthenticatedUsers = [SecurityIdentifier]::new("S-1-5-11")

# Create an access rule that grants Authenticated Users Read rights
$AUReadRule = [ActiveDirectoryAccessRule]::new($AuthenticatedUsers, [ActiveDirectoryRights]::GenericRead, [AccessControl.AccessControlType]::Allow)

# Create an ActiveDirectorySecurityObject, set current user as Owner
$SD = [ActiveDirectorySecurity]::new()
$SD.SetOwner($CurrentUser)

# Create a ModifyRequest for the ntSecurityDescriptor, set its value to the binary form of the SD
$ModifyRequest = [ModifyRequest]::new($Dn, [DirectoryAttributeOperation]::Replace, $Attr, $SD.GetSecurityDescriptorBinaryForm())

# Add the Owner control
[Void]$ModifyRequest.Controls.Add($SdOwnerControl)

# Send the request
Try
{
    "Taking ownership"
    $Response = [ModifyResponse]$Ldap.SendRequest($ModifyRequest)
}
Catch [DirectoryOperationException]
{
    $Response = $_.Exception.Response
}
"Result: {0}" -f $Response.ResultCode

""

# Now that we own the object, we can update the ACL to include Read rights for Authenticated Users, to ensure that we can read it in the future. To do so, we first need to get the SD of the object after we've taken ownership.
# We need to use a NULL filter here, otherwise the search won't return any objects as we are currently not allowed to read anything else than the SD.

$SearchRequest = [SearchRequest]::new($Dn, $null, [Protocols.SearchScope]::Base, $Attr)
[Void]$SearchRequest.Controls.Add($SdOwnerAndDaclControl)

Try
{
    "Retrieving security descriptor"
    $Response = [SearchResponse]$Ldap.SendRequest($SearchRequest)
}
Catch [DirectoryOperationException]
{
    $Response = $_.Exception.Response
}
"Result: {0}" -f $Response.ResultCode
""

# TODO: value count checking, etc

# Get the binary SD
$BinarySD = $Response.Entries[0].Attributes[$Attr][0]

# Create an ActiveDirectorySecurity object and load the binary SD
$CurrentSD = [ActiveDirectorySecurity]::new()
$CurrentSD.SetSecurityDescriptorBinaryForm($BinarySD)

# Add the AU Read rule

$CurrentSD.AddAccessRule($AUReadRule)

# Set the Owner to Enterprise Admins

$CurrentSD.SetOwner($EnterpriseAdminsSid)

# Attempt to update the SD

$ModifyRequest = [ModifyRequest]::new($Dn, [DirectoryAttributeOperation]::Replace, $Attr, $CurrentSD.GetSecurityDescriptorBinaryForm())

# Add the Owner and Dacl control
[Void]$ModifyRequest.Controls.Add($SdOwnerAndDaclControl)

# Send the request
Try
{
    "Updating SD"
    $Response = [ModifyResponse]$Ldap.SendRequest($ModifyRequest)
}
Catch [DirectoryOperationException]
{
    $Response = $_.Exception.Response
}
"Result: {0}" -f $Response.ResultCode
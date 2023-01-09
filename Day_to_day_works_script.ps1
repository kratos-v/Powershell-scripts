function Show-Menu
{
    param (
        [string]$Title = 'Main Menu'
    )
    Write-Host "`n`n`n================ $Title ================"
    
    Write-Host "1: User details"
    Write-Host "2: NSLookup"
    Write-Host "3: Trace Route"
    Write-Host "Q: Press 'Q' to quit."
}

function selection
{
    switch ($selection)
 {
     '1' {
$sam = Read-Host "Enter User account name(s):"
for ( $i = 0; $i -lt $sam.count; $i++ ) {
	Get-ADUser $sam[$i] -Properties *|select Name,DisplayName,Description,managedby,Manager,department,departmentnumber,emailaddress,allHROrganizationalUnit,PasswordLastSet,LastBadPasswordAttempt,LastLogonDate,enabled,lockedout,OfficePhone,telephoneNumber,telephoneAssistant
     }
     }
      
     '2' {
         $nameorip = Read-Host "Please enter the host name or IP address"
         Write-Host "`n"
	nslookup $nameorip
     } 
     '3' {
         $nameoriptrt = Read-Host "Please enter the host name or IP address"
         Write-Host "`n"
	tracert /h 15 $nameoriptrt
     } 
     'q' {
         return
     }
 }
}


Clear-Host
do
{
Show-Menu –Title 'Main Menu'
$selection = Read-Host "Please make a selection"
selection
}
until ($selection -eq 'q')

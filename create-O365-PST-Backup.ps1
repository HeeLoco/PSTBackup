##O365 PST BACKUP - PART I##

#author HeeLoco
#date 16.12.2019
#version: live 

#With this script it should be possible to create PST files and back them up.

#The password is not readably saved in a file.

#rclone is used
#winfsp was used

#If you want to create a password file please use the following command: "Read-Host -AsSecureString | ConvertFrom-SecureString | Out-File $myPasswordpath;"
#If the passwort file cant be found, the script will be get interactive 

#parameter section #############################################################################
Param(

    [parameter(Mandatory=$true)] #e.g. Test-HeeLoco
    [String]
    [ValidateNotNullOrEmpty()] 
    $SearchName,

    [parameter()] #e.g. All OR HeeLoco@Loco.planet OR Testuser@Loco.planet
    [String[]] #if not mandantory try to read a file 
    #[ValidateNotNullOrEmpty()] 
    $SearchTarget,

    [Switch]$NoVMDownload,
    [Switch]$NoO365Export,
    [Switch]$DebugModeOn
) 
#parameter section end ##########################################################################

#settings section begin ###########################################################################
    
#some vars and settings by author (do not change!) 
    $searchName = $Searchname + "-" + (get-date -UFormat "%Y-%m-%d");
    if($DebugModeOn){
        $searchName = "WinTask" + "-" + "2020-09-04";
    }
    $Error.Clear();
    [int]$myInputCount;

#define files and dirs
    $logFile = "$PSScriptRoot\Logs\Applog" + (get-date -UFormat "%Y-%m-%d") + ".txt";
    $logError = "$PSScriptRoot\Logs\Error\";
    $logUSer = "$PSScriptRoot\Logs\User\";
    $logExports = "$PSScriptRoot\Logs\Exports\";
    $cfgs = "$PSScriptRoot\cfgs\";

#some vars editable by admin (here you are allowed to change the values!)
    $myUsername = "HeeLoco@Loco.planet";
    $myPasswordpath = "$cfgs\mycreds.txt"; 

#Preparing the system install modules and azure cli 
    #todo: need to force it
    #      need to check for admin privs

    Install-Module az
    Invoke-WebRequest -Uri https://aka.ms/installazurecliwindows -OutFile .\AzureCLI.msi; Start-Process msiexec.exe -Wait -ArgumentList '/I AzureCLI.msi /quiet'

   #new auth style
   #Install-PackageProvider -Name NuGet -Force; Exit
   #Install-Module -Name PowerShellGet -Force; Exit # new module to get other module (ExchangeOnlineManagement)
   #Update-Module -Name PowerShellGet;Exit
   #Install-Module -Name ExchangeOnlineManagement
   #Import-Module ExchangeOnlineManagement; Get-Module ExchangeOnlineManagement
    #Update-Module -Name ExchangeOnlineManagement

#import modules
    Import-Module Az
    Import-Module ExchangeOnlineManagement

#Preparing the system check and create paths
    if(! (Test-Path $logError -PathType Container)){
        New-Item -Path $logError -ItemType Directory
    }

    if(! (Test-Path $logUSer -PathType Container)){
        New-Item -Path $logUSer -ItemType Directory;
    }
     
    if(! (Test-Path $logExports -PathType Container)){
        New-Item -Path $logExports -ItemType Directory;
    }

    if(! (Test-Path $cfgs -PathType Container)){
        New-Item -Path $cfgs -ItemType Directory;
    }

    #set logfile names after check
    $logError += (get-date -UFormat "%Y-%m-%d") + "Error.txt";
    $logUSer += (get-date -UFormat "%Y-%m-%d") + "User.txt";
    if(! ($DebugModeOn)){
        $logExports += (get-date -UFormat "%Y-%m-%d") + "Exports.txt";
    }
    else{
        $logExports += "2020-09-04" + "Exports.txt";
    }
    #start logging in file
    Start-Transcript -Path $logfile -Append;

    
#check for the password file
    if (! (Test-Path $myPasswordpath -PathType Leaf)){
        #If you want to create a password file please use the following command: 
        #Read-Host -AsSecureString | ConvertFrom-SecureString | Out-File $myPasswordpath;

        #create credential file if needed
        Write-Warning -Message "The password file was not found, please enter the passphrase";
        Read-Host -AsSecureString | ConvertFrom-SecureString | Out-File $myPasswordpath; #
    }
    #read file with non plain text password
    $Password = Get-Content $myPasswordpath | ConvertTo-SecureString; #Please check "Additional Info I" at the bottom                                      
    #create credential object 
    $Credentials = new-object -typename System.Management.Automation.PSCredential -argumentlist $myUsername ,$Password;

#Settings section end ##################################################################################################################

#functions section begin #######################################################################################################################
function dbg-fnLogin-O365 {
        #old method - not working anymore
        #$SccSession = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri https://ps.compliance.protection.outlook.com/powershell-liveid/ -Credential (Get-Credential) -Authentication "Basic" -AllowRedirection;
        #Import-PSSession $SccSession -Prefix cc | Out-Null;
 
}

function fnLogin-O365 {

    Write-Host "Login O365";
    #create and import session
    try {
        #$SccSession = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri https://ps.compliance.protection.outlook.com/powershell-liveid/ -Credential $Credentials -Authentication "Basic" -AllowRedirection;
        #Import-PSSession $SccSession -Prefix cc | Out-Null; ##use prefix to find possible commands easier
        #Connect-ExchangeOnline -Credential $Credentials -ShowProgress $true;
        Connect-IPPSSession -ConnectionUri https://ps.compliance.protection.outlook.com/powershell-liveid/ -Credential $Credentials;
    }catch{
        #write in log
        $Error | out-file -FilePath $logError;
        Write-Warning -Message "Session issue" 
        #send notification
        Send-MailMessage -From 'O365 PST Backup <Service@loco.planet>' -To 'HeeLoco <HeeLoco@loco.planet>' -Subject 'Failure notification - Session' -Body "Session issue was detectet`n $Error `n" -SmtpServer 'MailServer.loco.planet';
        #end session
        Get-PSSession | Remove-PSSession
        #stop write in file
        Stop-Transcript;
        #end script
        return 666;
    }
}

function fnLogin-Azure {

    Write-Host "Login Azure";
    #Login zu Azure
    try {
        Login-AzAccount -Credential $Credentials   ##failed needs token but error appears at another point (compliance search issue!!!!)
        az login -u $Credentials.UserName -p $Credentials.GetNetworkCredential().Password
        #set current subscription
        az account set --subscription 00000000-0000-0000-0000-000000000000
    }catch{
        #write in log
        $Error | out-file -FilePath $logError;
        Write-Warning -Message "Session issue" 
        #send notification
        Send-MailMessage -From 'O365 PST Backup <Service@loco.planet>' -To 'HeeLoco <HeeLoco@loco.planet>' -Subject 'Failure notification - Session' -Body "Session issue was detectet`n $Error `n" -SmtpServer 'MailServer.loco.planet';
        #end session
        Get-PSSession | Remove-PSSession
        #stop write in file
        Stop-Transcript;
        #end script
        return 666;
    }
}

function Start-O365Procedure([string]$searchName, [string[]]$SearchTarget){
    
    #set export name
    $exportName = $searchName + "_Export";
    $exportName | Out-File -FilePath $logExports -Append;

    #create Compliance Search ()
    Write-Host "create search $searchName with $SearchTarget" -ForegroundColor Cyan;
    New-ComplianceSearch -name $searchName -ExchangeLocation $SearchTarget; #most important

    if($Error){# no $LASTEXITCODE no try catch possible
        #write in log
        $Error | out-file -FilePath $logError;
        Write-Warning -Message "New-ComplianceSearch issue";
        #send notification
        Send-MailMessage -From 'O365 PST Backup <Service@loco.planet>' -To 'HeeLoco <HeeLoco@loco.planet>' -Subject 'Failure notification - Compliance Search' -Body "Compliance Search issue was detectet`n $Error `n" -SmtpServer 'MailServer.loco.planet'
        #end session
        Get-PSSession | Remove-PSSession
        #end script run with fail
        Stop-Transcript;
        return 666;
    }

        #Get-ccComplianceSearch | Select-Object -Property Name, Status, JobEndTime, ObjectState

    #start search 
    Start-Sleep -Seconds 15;
    Write-Host "Start search $searchName with $SearchTarget" -ForegroundColor Yellow;
    Start-ComplianceSearch -Identity $searchName;

    #delay until its created
    do{   
        Start-Sleep -Seconds 15; 
    }while((Get-ComplianceSearch -Identity $Searchname).status -ne "Completed") 

    #export search
    Write-Host "Start export $searchName with $SearchTarget and $exportName" -ForegroundColor Green;
    New-ComplianceSearchAction -SearchName $searchName -Export -Format FXStream -ExchangeArchiveFormat PerUserPst;

    #add here some try and catch OR $Error check!!!


    Start-Sleep -Seconds 15;


  #  Write-Host("Some Info about the job");
    #name
 #   Write-Host $searchName;
 #   Write-Host $exportName;
    #export duration
#    Write-Host $myResult.Duration;
    #URL
 #   Write-Host $myResult.Containerurl;
    #SAS token 
 #   Write-Host $myResult.SAStoken;
    #Log all further information 
 #   Write-Host $myResult.Totalestimatedbytes;
 #   Write-Host $myResult.Totaltransferredbytes;
    
}

function Check-O365Progress([string]$ExportName){

    #result object neeeded ?!?!?!
    #$myResult = @();

    #fnLogin-O365;

    #define array to get an array as expected
    $arrResult = @();

    #create empty hashtable 
    $myHash = [Ordered] @{};
    
    #export needed info into temp
    $tempResult = Get-ComplianceSearchAction -Identity $ExportName -Details -IncludeCredential | Select-Object -ExpandProperty Results 
    #split result string into smaller parts
    $arrResult = $tempResult.Split(";");

    foreach ($item in $arrResult){
    
        #split parts into key value pairs 
        $arrItem = $item.Split(":",2); #split at ":"

        # $arrItem[0] #key
        # $arrItem[1] #value

        #manipulate the hashtable to create a custom object
        $myHash += @{$arrItem[0].Replace(" ","") = $arrItem[1].Replace(" ","")};      ##added .Replace(" ","") for removing spaces
    }
    #create new object with extracted info
    $myResult = New-Object -TypeName psobject -Property $myHash;

    #end session
    #Get-PSSession | Remove-PSSession;

    #show Progress
    Write-Host ($ExportName);
    Write-Host ($myResult.Progress);

    if($myResult.Progress -notmatch '100'){
        return 999;
    }
    return 0;
}

function Get-O365SearchResult([string]$ExportName){
    
    #fnLogin-O365;

    #define array to get an array as expected
    $arrResult = @();

    #create empty hashtable 
    $myHash = [Ordered] @{};
    
    #export needed info into temp
    $tempResult = Get-ComplianceSearchAction -Identity $ExportName -Details -IncludeCredential | Select-Object -ExpandProperty Results 
    #split result string into smaller parts
    $arrResult = $tempResult.Split(";");

    foreach ($item in $arrResult){
    
        #split parts into key value pairs 
        $arrItem = $item.Split(":",2); #split at ":"

        # $arrItem[0] #key
        # $arrItem[1] #value

        #manipulate the hashtable to create a custom object
        $myHash += @{$arrItem[0].Replace(" ","") = $arrItem[1].Replace(" ","")};      ##added .Replace(" ","") for removing spaces
    }
    #create new object with extracted info
    $myResult = New-Object -TypeName psobject -Property $myHash;

    #add exportname to 
    $myResult | Add-Member -MemberType NoteProperty -Name ExportName -Value $ExportName

    #save all usernames to log
 #  Write-Host("save username to log");
   Get-ComplianceSearchAction -Identity $ExportName -Details -IncludeCredential | Select-Object -ExpandProperty ExchangeLocation | Out-File -FilePath $logUSer -Append; #added append for multi exports


    #end session
    #Get-PSSession | Remove-PSSession;

    return $myResult;
}
#function section end #########################################################################################################################

#main ############################################################################################
Send-MailMessage -From 'O365 PST Backup <Service@loco.planet>' -To 'HeeLoco <HeeLoco@loco.planet>' -Subject 'Job started' -Body " $Searchname " -SmtpServer 'MailServer.loco.planet';
#dont do the O365 Part
if(! ($NoO365Export)){
    #Login O365
    if((fnLogin-O365) -eq 666){
        return 666;
    }


    ### ADD HERE THE SPLITTING PART ## USE ENTRIES OF A FILE ############################################!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!'###############
    if($SearchTarget){
        $myReturn = Start-O365Procedure -searchName $SearchName -SearchTarget $SearchTarget
        if($myReturn -eq 666){
            return 666;
        }
    }
    else{
    
    #get user and filter ".biz" and ".onmicrosoft.com" to get a clean list by using regex
    #check for recipienttype instead of biz and other extensions
    #$myInput = Get-ccUser | Where-Object { $_.MicrosoftOnlineServicesID -notmatch ".biz$" } | Where-Object { $_.MicrosoftOnlineServicesID -notmatch ".onmicrosoft.com$" } | Where-Object { $_.MicrosoftOnlineServicesID -notmatch "^schulung" } | Select-Object -Property MicrosoftOnlineServicesID
    $myInput = Get-User | Where-Object {$_.RecipientType -eq "MailUser"} | Select-Object -Property MicrosoftOnlineServicesID;
    
    #prepare and fill Array
    #read file per line in array
    #$myInput = Get-Content -Path C:\INSTALL\bla.txt

    #determine needed array size
    #[int]$myInputCount = $myInput.Count
    #$myInputCount = [math]::ceiling($myInput.Count / 20) #equal number of searches rounded up

    #UPDATE: MS has a limit of 10 Exports at a time
    $myInputCount = [math]::ceiling($myInput.Count / 10) #change to maximum 10 exports 


    #create true multi-dimensional array(not jagged)
    #$myMultiDimArray = New-Object 'object[,]' $myInputCount,20;
    $myMultiDimArray = New-Object 'object[,]' 10, $myInputCount;

    $myInput.Count
    [int]$k = 0;

    <# old version
    #fill multi array
    for($i = 0; $i -lt $myInputCount; $i++){
        for($j = 0; $j -lt 20; $J++){
            $myMultiDimArray[$i, $j] = $myInput[$k]; #"$i" + " " + "$j";
            $myInput[$k];
            $k++;  
            $k;             
            #"$i" + "$j" + " "
        }
        #"`n"
    }
    #>
    
    #new version
    #fill multi array
    for($i = 0; $i -lt 10; $i++){
        for($j = 0; $j -lt $myInputCount; $J++){
            $myMultiDimArray[$i, $j] = $myInput[$k]; #"$i" + " " + "$j";
            $myInput[$k].MicrosoftOnlineServicesID;
            $k++;  
            #$k;             
            #"$i" + "$j" + " "
        }
        #"`n"
    }

    #use the created packages to create and start exports

<#
    #loop each "package"
    for($i = 0; $i -lt $myInputCount; $i++){
        #create empty string array
        #$SearchTarget = $null;
        $SearchTarget = @();

        #fill string searchtarget
        for($j = 0; $j -lt 20;$j++){
            
            #check if multi array is not empty
            if($myMultiDimArray[$i, $j]){
                #$SearchTarget += "," + $myMultiDimArray[$i, $j];
                $SearchTarget += $myMultiDimArray[$i, $j].MicrosoftOnlineServicesID;
            }
        }
       
        #prepare tempsearchname as param
        $tempSearchName = $SearchName + "-" + $i; 

        #call function
        $myReturn = Start-O365Procedure -searchName $tempSearchName -SearchTarget $SearchTarget
        if($myReturn -eq 666){
            return 666;
        }
    }
    #>

    #new version
    #loop each "package"
    for($i = 0; $i -lt 10; $i++){
        #create empty string array
        #$SearchTarget = $null;
        $SearchTarget = @();

        #fill string searchtarget
        for($j = 0; $j -lt $myInputCount;$j++){
            
            #check if multi array is not empty
            if($myMultiDimArray[$i, $j]){
                #$SearchTarget += "," + $myMultiDimArray[$i, $j];
                $SearchTarget += $myMultiDimArray[$i, $j].MicrosoftOnlineServicesID;
            }
        }
       
        #prepare tempsearchname as param
        $tempSearchName = $SearchName + "-" + $i; 

        #call function
        $myReturn = Start-O365Procedure -searchName $tempSearchName -SearchTarget $SearchTarget
        if($myReturn -eq 666){
            return 666;
        }
    }
    }
    ############################################################

    write-host ("back to main");

    #end session
    Get-PSSession | Remove-PSSession;
}

#define var as array to get the count method
$myExports = @()
#$myContent = Get-Content -Path $logExports;
#$myExports = Get-Content -Path 'C:\Users\ott3101\OneDrive - GEUTEBRÜCK GmbH\it\Azure PowerShell\Exchange-PST-Project\Logs\Exports\Exports.txt'

foreach($line in (Get-Content -Path $logExports)){
    $myExports += $line;
}

$myInputCount = $myExports.count;
#OR AS ARRAY!! if no file export is needed. with this build I am allowed to start directly from here
Write-Host ("anzahl der exports:");
write-host ($myInputCount)

#check if all exports are done
do{
    if(! ($DebugModeOn)){
        Start-Sleep -Seconds 6000; #6000 1h wait duration ###############################################################################################################
    }
    else{
        Start-Sleep -Seconds 15; #testing: set to 15
    }

    #reset counter
    $myCounterDoneExport = 0;

    #login
    fnLogin-O365;
    foreach($Export in $myExports){

        $myTempReturn = Check-O365Progress -ExportName $Export;
        if($myTempReturn -eq 0){ 
            $myCounterDoneExport++;
        }
        #self healing point
      #  elseif($myTempReturn -eq 666){
      #      return 666;
      #  }
    }
    #show counter 
    Write-Host ("$myCounterDoneExport of $myInputCount jobs done");

    #end session
    Get-PSSession | Remove-PSSession;
}while($myCounterDoneExport -ne $myInputCount)

write-host "All exports are done"!;

#get SAS URL and NAME
$myFullResult = @();
fnLogin-O365;
foreach($Export in $myExports){

    $myFullResult += Get-O365SearchResult -ExportName $Export;  
    #$myFullResult += Get-O365SearchResult -ExportName testEOT-2020-02-04_Export;
}
#end session
Get-PSSession | Remove-PSSession;
    
write-host ($myFullResult | Select-Object *)
    
#calculate duration of all exports
#$myExportDuration = 0;
#$myExportDuration += 


#my Result of the O365 function
#write-host ($myReturn);
#$myDuration = $myReturn.Duration;

#Azure Part starts here

#check switch parameter
if($NoVMDownload){

    #send message 
    Write-Host ("sending email");
    Send-MailMessage -From 'O365 PST Backup <Service@loco.planet>' -To 'HeeLoco <HeeLoco@loco.planet>' -Subject 'Success notification - Job done' -Body " $Searchname `n Duration of export creation: $myDuration `n There will be NO EXPORT! (switch parameter is activated)" -SmtpServer 'MailServer.loco.planet';

}else{

#login azure
fnLogin-Azure

#set some names
$myRessgroupName = "PSTBackUPGroup";
$myVMName = "PSTExportVM";
$myNSGName = $myVMName + "NSG";
$myAdminUserName = "local-HeeLoco";
$myAdminPassword = "SecurePassword123456789!987654321!"

#create credential object
$myTempPassword = $myAdminPassword | ConvertTo-SecureString -AsPlainText -Force;                                    
$myVMCredentials = new-object -typename System.Management.Automation.PSCredential -argumentlist $myAdminUserName ,$myTempPassword;

#create VM 
Write-Host "Create ressource group";
az group create --name $myRessgroupName --location northeurope
Write-Host "Create VM";
az vm create -g $myRessgroupName --name $myVMName --image win2019datacenter --admin-username $myAdminUserName --admin-password $myAdminPassword --license-type Windows_Server --size Standard_DS3_v2

#disk create and attach
Write-Host "Create disk";
az vm disk attach --vm-name $myVMName --caching ReadWrite --new --size-gb 2048 --sku Standard_LRS --name 2TB-StandardHDD -g $myRessgroupName
#az vm disk attach --vm-name $myVMName --caching ReadWrite --new --size-gb 2048 --sku Premium_LRS --name 2TB-PremiumSSD -g $myRessgroupName

#own ip - todo: add own ip as --source-address-prefixes in nsg rules
#nslookup myip.opendns.com. resolver1.opendns.com
#Resolve-DnsName -Name myip.opendns.com -Server resolver1.opendns.com
$myDNSResolve = Resolve-DnsName -Name myip.opendns.com -Server resolver1.opendns.com | select IPAddress
$myDNSResolve.IPAddress

#set nsg rules 
Write-Host "set nsg rules";
az network nsg rule update -g $myRessgroupName --nsg-name $myNSGName -n rdp --access allow --source-address-prefixes 123.456.789.123
az network nsg rule create -g $myRessgroupName --nsg-name $myNSGName -n RemotePS --priority 1001 --access allow --direction inbound --destination-port-ranges 5986 --protocol TCP --source-port-ranges * --source-address-prefixes 123.456.789.123

#set further preps / in this case enable PowerShell Remoting and disable windows update
Write-Host "Enable remote PS and disable Windows Update";
az vm run-command invoke --command-id EnableRemotePS --name $myVMName -g $myRessgroupName
az vm run-command invoke --command-id DisableWindowsUpdate --name $myVMName -g $myRessgroupName

#Start-Sleep -Seconds 60;
#run preps
#another try copy files to VM via PowerShell Remoting

#enable on machine
#az vm run-command invoke --command-id RunPowerShellScript --name $myVMName -g $myRessgroupName --scripts "Enable-PSRemoting -Force";
#az vm run-command invoke --command-id EnableRemotePS --name PSTExportVM -g PSTBackUpgroup
#az vm run-command invoke --command-id RunPowerShellScript --name $myVMName -g $myRessgroupName --scripts "Set-Item WSMan:localhost\client\trustedhosts -value * -Force";
 
#########################################################################

#get ip of VM
#$myVMip = az vm list-ip-addresses -g PSTBackUpgroup -n PSTExportVM --query "[].virtualMachine.network.publicIpAddresses[*].ipAddress" -o tsv
$myVMip = az vm list-ip-addresses -g $myRessgroupName -n $myVMName --query "[].virtualMachine.network.publicIpAddresses[*].ipAddress" -o tsv
Write-Host $myVMip

#set local settings
#allow connection to remote machines
Set-Item WSMan:localhost\client\trustedhosts -value $myVMip.ToString() -Force #to limmit ip addresses
#Set-Item WSMan:localhost\client\trustedhosts -value * -Force

#create session to VM
Write-Host "Create PSSession to VM";
$mySO = New-PsSessionOption –SkipCACheck -SkipCNCheck;
$myVMSession = New-PSSession -ComputerName $myVMip -Credential $myVMCredentials -UseSSL -SessionOption $mySO;

#copy and extract items to/in VM
Write-Host "invoke copy and extraction";
Copy-Item -ToSession $myVMSession -Path $PSScriptRoot\Tools.zip -Destination C:\Tools.zip
Invoke-Command -Session $myVMSession -ScriptBlock {Expand-Archive -Path C:\Tools.zip -DestinationPath C:\Tools}
#azure cli equivalent of the extration part:
#az vm run-command invoke --command-id RunPowerShellScript --name $myVMName -g $myRessgroupName --scripts 'Expand-Archive -Path C:\Files.zip -DestinationPath C:\FilesExtracted'
Copy-Item -ToSession $myVMSession -Path $PSScriptRoot\copy-O365-PST-Backup.ps1 -Destination C:\Tools\copy-O365-PST-Backup.ps1

#init, part and give attached disk a name
Write-Host "init, part and give attached disk a name";
Invoke-Command -Session $myVMSession -ScriptBlock {$myAttDisk = Get-Disk | Where-Object -Property PartitionStyle -eq "RAW"; Initialize-Disk -Number $myAttDisk.Number -PartitionStyle GPT; New-Partition -DiskNumber $myAttDisk.Number -UseMaximumSize -AssignDriveLetter | Format-Volume -FileSystem NTFS -NewFileSystemLabel "2TB-Space";};  #-Confirm:$false to test!!!

#get the drive letter of the attached disk
Write-Host "get drive letter";
$myVMAttDrive = Invoke-Command -Session $myVMSession -ScriptBlock {(Get-Partition -DiskNumber $myAttDisk.Number)}
$myVMAttDriveLetter = ($myVMAttDrive | Where-Object {$_.Type -eq "Basic"}).Driveletter
write-host $myVMAttDriveLetter;
#it should be only exist one letter!

#get time before job(s)
$myStartTime = Get-date;

Write-Host "invoke script";
#with waiting and output in console
#Invoke-Command -Session $myVMSession -ScriptBlock {& C:\Tools\copy-O365-PST-Backup.ps1 -myobject $using:myFullResult -driveletter $using:myVMAttDriveLetter}
#invoking without waiting 
Invoke-Command -Session $myVMSession -ScriptBlock {& C:\Tools\copy-O365-PST-Backup.ps1 -myobject $using:myFullResult -driveletter $using:myVMAttDriveLetter} -AsJob
#Invoke-Command -Session $myVMSession -ScriptBlock {Start-Process powershell.exe -ArgumentList "C:\Tools\copy-O365-PST-Backup.ps1 -myobject $using:myFullResult -driveletter $using:myVMAttDriveLetter"}
#Invoke-Command -Session $myVMSession -ScriptBlock {Start-Process powershell.exe -ArgumentList `"C:\Tools\copy-O365-PST-Backup.ps1`", `"$using:myFullResult`", `"$using:myVMAttDriveLetter`"}
#Invoke-Command -InDisconnectedSession -SessionName asd -ScriptBlock {"bla"}
#Get-PSSession | Remove-PSSession;
#log out azure 
Logout-AzAccount;

#wait until VM is offline 
do{
    Start-sleep -Seconds 10800; #3h
    fnLogin-Azure;
    #$myVMStatus = az vm get-instance-view --name PSTExportVM --resource-group PSTBackUpgroup --query instanceView.statuses[1] | ConvertFrom-Json
    $myVMStatus = az vm get-instance-view --name $myVMName --resource-group $myRessgroupName --query instanceView.statuses[1] | ConvertFrom-Json
    Write-Host "check if VM is off";
    Logout-AzAccount;
}while($myVMStatus.code -eq "PowerState/running")

#get time after job(s)
$myEndTime = Get-date;
$myFullTimespan = New-TimeSpan -Start $myStartTime -End $myEndTime;

Write-Host "Timespan of working VM";
Write-Host $myFullTimespan;

Send-MailMessage -From 'O365 PST Backup <Service@loco.planet>' -To 'HeeLoco <HeeLoco@loco.planet>' -Subject 'Success notification - Job done' -Body " $Searchname `n Timespan of working VM: $myFullTimespan " -SmtpServer 'MailServer.loco.planet';

<#
#disk attach & create 
az vm disk attach --vm-name PSTExportVM --caching ReadWrite --new --size-gb 2048 --sku Standard_LRS --name 2TB-StandardHDD -g PSTbackupgroup

$myAttDisk = Get-Disk | Where-Object -Property PartitionStyle -eq "RAW"; Initialize-Disk -Number $myAttDisk.Number -PartitionStyle GPT; New-Partition -DiskNumber $myAttDisk.Number -UseMaximumSize -AssignDriveLetter | Format-Volume -FileSystem NTFS -NewFileSystemLabel "2TB-Space"; (Get-Partition -DiskNumber $myAttDisk.Number).DriveLetter;

#get number of Disk for further usage
$myAttDisk = Get-Disk | Where-Object -Property PartitionStyle -eq "RAW"

#check if it is only one!

#show number
$myAttDisk.Number

#Initialize-Disk -Number (Get-Disk | Where-Object -Property PartitionStyle -eq "RAW").Number -PartitionStyle MBR
Initialize-Disk -Number $myAttDisk.Number -PartitionStyle GPT

#create partition and format volume 
New-Partition -DiskNumber $myAttDisk.Number -UseMaximumSize -AssignDriveLetter | Format-Volume -FileSystem NTFS -NewFileSystemLabel "2TB-Space" #-Confirm:$false zu testen

(Get-Partition -DiskNumber $myAttDisk.Number).DriveLetter
#>

<#
Now, copy some files from a remote session to the local server:

$SourceSession = New-PSSession -ComputerName HALODC01

Copy-Item -FromSession $SourceSession -Path "C:\Users\Administrator\desktop\scripts\" -Destination "C:\Users\administrator\desktop\" -Recurse
#>

############################################################################
#download and extract files
#Write-Host "invoke download";
#az vm run-command invoke --command-id RunPowerShellScript --name $myVMName -g $myRessgroupName --scripts 'wget -uri https://storage.online/12463531546 -outfile C:\Files.zip'

#dump object to VM
#az vm run-command invoke --command-id RunPowerShellScript --name $myVMName -g $myRessgroupName --scripts 

#Write-Host "invoke script";
#script in file
#az vm run-command invoke --command-id RunPowerShellScript --name $myVMName -g $myRessgroupName --scripts 'Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope LocalMachine'
#az vm run-command invoke --command-id RunPowerShellScript --name $myVMName -g $myRessgroupName --scripts "& C:\Users\ott3101\OneDrive - GEUTEBRÜCK GmbH\IT\Azure PowerShell\Exchange-PST-Project\copy-O365-PST-Backup.ps1" --parameters "exportName=$exportName" "myResult=$myResult"

#az vm run-command invoke --command-id RunPowerShellScript --name $myVMName -g $myRessgroupName --scripts "Start-Process -FilePath C:\FilesExtracted\copy-O365-PST-Backup.ps1 -ArgumentList -exportName $exportName -myResult $myResult"
#$mycommand = 'powershell C:\FilesExtracted\copy-O365-PST-Backup.ps1 -exportName {0} -myResult {1}' -f $exportName, $myResult;
#az vm run-command invoke --command-id RunPowerShellScript --name $myVMName -g $myRessgroupName --scripts $mycommand


#Start-Process powershell.exe -ArgumentList "-file C:\MyScript.ps1", "Arg1", "Arg2"
#script inline
#az vm run-command invoke  --command-id RunPowerShellScript --name win-vm -g my-resource-group --scripts 'param([string]$arg1,[string]$arg2)' 'Write-Host This is a sample script with parameters $arg1 and $arg2' --parameters 'arg1=somefoo' 'arg2=somebar'

}

#Basic Clean up #############################
    fnLogin-Azure;
    az group delete --name $myRessgroupName --yes
    #logout
    az logout;
    Logout-AzAccount;
    #end sessions
    #Get-PSSession | Remove-PSSession;
    #end transcript
    Stop-Transcript;
#cleanup end #################################
<#
    #logout
    Logout-AzAccount;
    #end session
    Get-PSSession | Remove-PSSession;
    #end transcript
    Stop-Transcript;
#>

<# Additional Info I
When you use the command ConvertTo-SecureString it encrypts the plaintext password with the encryption key on the local machine, under your user account. 
This means that if you export it to xml, you can only use it on that same local machine.

The minute you copy the xml file to another machine and try to import the credential object, 
it won't work because it will be trying to decrypt it with it's local keys which don't match. 
(hence the error message). 
This is an important security measure as it prevents me from copying the file and using it on another computer.



If you need to have the user account on another computer to run something, then there are Three options:

(Unsecured) Use Plain Text

(Most secure) Create the credential object on each remote computer that you need it. 

(Least secure) When you create the credential with ConvertTo-SecureString you can specify the -Key or -SecureKey parameter. 
This way instead of using the local encryption keys, it will use the one you specify. 
Then in your script, you provide the same key to decrypt it.

#>

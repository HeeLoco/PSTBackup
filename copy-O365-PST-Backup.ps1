##O365 PST BACKUP - PART II##

#author HeeLoco
#date 16.12.2019
#version: live 

#With this script it should be possible to create PST files and back them up.

#rclone is used
#winfsp was used

#If you want to create a password file please use the following command: "Read-Host -AsSecureString | ConvertFrom-SecureString | Out-File Path\ToFile;"
#If the passwort file cant be found, the script will be get interactive 


#at this point the files should be unzipped on the remote machine

#parameter section
Param(

    [parameter(Mandatory=$true)] #
    $myobject,

    [parameter(Mandatory=$true)] #
    $DriveLetter
) 
$myLog = "C:\mylog.txt";

Start-Transcript -Path $myLog -Append;
$myRoot = "C:\Tools";

$exportLocation = $DriveLetter + ":\Drop" #enter the path to your export here !NO TRAILING BACKSLASH!
$exportEXE = "$myRoot\UnifiedExportTool\microsoft.office.client.discovery.unifiedexporttool.exe" #path to your microsoft.office.client.discovery.unifiedexporttool.exe file. Usually found somewhere in %LOCALAPPDATA%\Apps\2.0\

#check if winfsp is installed - todo: remove this part
if(! (Test-Path -Path ${env:ProgramFiles(x86)}\winfsp\bin\fsptool-x64.exe -PathType Leaf)){
    #get the executable
    $myItem = Get-ChildItem -Path "$myRoot\WinFsp" -Filter "*winfsp*";
    #check if it is only one!
    if ($myItem.count -ne 1){
        #if not get the newest
        #return $false
        $myItem = $myItem | sort-Object LastWriteTime -Descending | Select-Object -First 1
    }
    $myItem = $myItem.FullName;
    Write-Host "install Winfsp";
    Start-Process msiexec.exe -Wait -ArgumentList "/I `"$myItem`" /quiet";
}  
    #rclone? 
    #https://downloads.rclone.org/rclone-current-windows-amd64.zip
    #https://downloads.rclone.org/rclone-current-windows-386.zip

    #rclone! use WinFsp and rclone to create a connection to blob storage and mount it in user scope
    #create rclone config
    Write-Host "create rclone config";
    & $myRoot\rclone\rclone.exe config create myBlob azureblob account HeeLocoblob key 0000000000000000000000000000000000000000000000000000000000000000000000000000000000000==

function Start-PSTDownload([string]$exportName, [string]$exportContainerUrl, [string]$exportSAStoken){

    #copy   
    #use the tool to download and copy the export

    # Download the exported files from Office 365
    Write-Host "Initiating download of export $exportName `nSaving to: $exportLocation" -ForegroundColor Green;
    Write-Host "$exportContainerUrl";
    Write-Host "$exportSAStoken";
    Write-Host "`n-------`n";

    $myArguments = "-name ""$exportName""","-source ""$exportContainerUrl""","-key ""$exportSAStoken""","-dest ""$exportLocation""","-trace true";
    #start and wait
    try{
        Start-Process -FilePath $exportEXE -ArgumentList $myArguments -wait; #wait is needed because parallel running processes of the tool are not possible (at the moment - todo?)
    }
    catch{

        #write in log
        $Error #| out-file -FilePath $logError;
        Write-Warning -Message "Start-Process issue";
        #send notification
        Send-MailMessage -From 'O365 PST Backup <Service@loco.planet>' -To 'HeeLoco <HeeLoco@loco.planet>' -Subject 'Failure notification - Starting copy Process' -Body "Copy Process issue was detectet`n $Error `n" -SmtpServer 'MailServer.loco.planet'
        return 666;
    }
    #otherwise check $error var?
}

#main

#get time before job(s)
$myStartTime = Get-date;

#determine if there is only one object
if($myobject.count -gt 1){
    Write-Host "multiple objects found!!"
    foreach($currobj in $myobject){
        $myRemoteFolderName = $currobj.ExportName;
        $currobj.ExportName;
        $currobj.containerurl;
        $currobj.SAStoken;
        $myReturn = Start-PSTDownload -exportName $currobj.ExportName -exportContainerUrl $currobj.containerurl -exportSAStoken $currobj.SAStoken
    }
}
else{
    Write-Host "only one object found!"
    $myRemoteFolderName = $myobject.ExportName;
    $myobject.ExportName;
    $myobject.containerurl;
    $myobject.SAStoken

    $myReturn = Start-PSTDownload -exportName $myobject.ExportName -exportContainerUrl $myobject.containerurl -exportSAStoken $myobject.SAStoken
}
#check return of function
if($myReturn -eq 666){
    #end script run with fail
    Stop-Transcript;
    return 666;
}
#clean up the remote folder name split and get only the first part
$myRemoteFolderName = $myRemoteFolderName.split("_")[0];

#check process if job(s) is/are running only needed as backup for the wait param or other unplanned reactions of the process
Write-Host "wait until all jobs are done(checking processes)";
while(Get-Process -name microsoft.office.client.discovery.unifiedexporttool -ErrorAction SilentlyContinue){

    Start-Sleep -Seconds 60; 
}

#get time after copy job 
$myEndTime = Get-date;
$myCopyTimespan = New-TimeSpan -Start $myStartTime -End $myEndTime;

Write-Host "time to download:"
Write-Host $myCopyTimespan;

Stop-Transcript
#copy transcript to export location
Copy-Item -Path $myLog -Destination $exportLocation;

#$myRemoteFolderName = (get-date -UFormat "%Y-%m-%d");

#start uploading to blob
Start-Process -FilePath "$myRoot\rclone\rclone.exe" -ArgumentList "sync F:\Drop myBlob:AutomatedUploads/$myRemoteFolderName" -wait -NoNewWindow


Start-Sleep -Seconds 10;
Stop-Computer -Force

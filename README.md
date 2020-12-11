# PSTExport

This serves as an automated monthly backup of the mailboxes. An export is executed in Exchange Online, an Azure VM is created, which backs up the export to an Azure Blob Storage.

The scripts can still be improved in some places, but currently this solution runs successfully.

The first script is triggered via task scheduler by an on prem vm. 

The frist part of this solution is about creating the exports in Exchange Online. This takes a while. So we can safe money while Exchange Online is working and we use the on prem vm.

## Note 
Exchange has some limits regarding parallel exports and the limit of downloaded data.
I my case I set the limit to 10. Find it here: Script create-O365-PST-Backup.ps1 line 360

Since the authentication style changed we need a new import/install-module path. Run the script the first time manually and check if there are any more changes like this.

# PSTExport

This serves as an automated monthly backup of the mailboxes. An export is executed in Exchange Online, an Azure VM is created, which backs up the export to an Azure Blob Storage.

The scripts can still be improved in some places, but currently this solution runs successfully.

The first script is triggered via task scheduler by an on prem vm.

## Note 
Further information will follow 

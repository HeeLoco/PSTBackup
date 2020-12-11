# PSTExport

This serves as an automated monthly backup of the mailboxes. An export is executed in Exchange Online, an Azure VM is created, which backs up the export to an Azure Blob Storage.

The scripts can still be improved in some places, but currently this solution runs successfully.

The first script is triggered via task scheduler by an on prem vm. 

The frist part is about creating the exports in Exchange Online. This takes a while. So we can safe money while Exchange Online is working.

## Note 
Further information will follow 

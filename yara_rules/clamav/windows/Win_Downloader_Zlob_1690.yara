rule Win_Downloader_Zlob_1690
{
strings:
	$a0 = { e976d11cdae3901c13fed89d36573b0c2c6f9acdc56612b95a4dd5cca5486a121d6fda25267634c6882b3828ea5e4af8e3da3567124058adebcaf83a3a9d68cba61648d76448c38da5b876e32811ceb7cc5dee0a5044784cf27d }

condition:
	$a0
}

        

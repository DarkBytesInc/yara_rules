rule Win_Downloader_Dyfuca_36
{
strings:
	$a0 = { 54414300534a84fbb7da776172655c2573026bfbaab6df246e7565204d2a69494941546c15bf726e6574204fb16d146321bb3b7200333600bf }

condition:
	$a0
}

        

rule Win_Downloader_Banload_666
{
strings:
	$a0 = { 333d9e11b99cc774f4c2f4c61131384cead5cb8269e3273ebab0bc487112cdf586a3ea96d61c4afb535091d88561dd051294e48beadba94fe4509f8bc6263e4da3e3292ffb18b90daf9b073f6910199028ce13dc76e914ca71db }

condition:
	$a0
}

        

rule Win_Downloader_Zlob_2313
{
strings:
	$a0 = { 59f597276117b02ad57c5ee1808cfd39060ca23ed6a87c7b193aaf1494140bb8a8554332e5b3d01f1efe43bcad318878c738c7c3dd0092eac7b013127d098eb5d95328d6b4114e9cffd37258f2d7 }

condition:
	$a0
}

        

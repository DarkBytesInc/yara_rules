rule Win_Downloader_Delf_2066
{
strings:
	$a0 = { 2dd52d8fb788753faa2e3dd0b46f7f735df3f2d2aa5286d60fcbf1062e8a4d6b57ac58b572f9dd2b572dcf5bbdbc60d58ac3fbf7ec6e16ebf636afc076f7fe158fd63dbea77679cb9ee67fce17e67737ff58dadbbabf25a3b62ea3a979ff0f9b77ff68774bf5dec7c4bae6c7eac48c3a637df55ea3b7bcee405d862147f3eeda }

condition:
	$a0
}

        

rule Win_Downloader_VBS_151
{
strings:
	$a0 = { 6e6577776f7264733d756e657363617065286b657973293b[0-14]286e6577776f726473293b }

condition:
	$a0
}

        

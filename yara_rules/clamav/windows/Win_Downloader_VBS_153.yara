rule Win_Downloader_VBS_153
{
strings:
	$a0 = { 733d73706c6974286b2c22402229[0-30]743d742b636872286576616c287328695f292929 }

condition:
	$a0
}

        

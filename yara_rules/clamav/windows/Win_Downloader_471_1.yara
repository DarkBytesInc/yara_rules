rule Win_Downloader_471_1
{
strings:
	$a0 = { f9392da00b2fab8df658cb9099c514aebd64c19c119be8bf573931898beffc157a11676369d3864d4cd24223674cbccfde658194c234ecd5c45148a444050cce15faa1d0af221dcf5761078f5296 }

condition:
	$a0
}

        

rule Win_Downloader_5466_1
{
strings:
	$a0 = { f7d1495168809600106a0168c496001068989600106801000080ff157c710010 }

condition:
	$a0
}

        

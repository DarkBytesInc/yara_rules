rule Win_Downloader_705_1
{
strings:
	$a0 = { ada26a8464495815c1d23fe6b0a614ca170a9652f89e78300fa5bb6617731d416efee72b8ecb1ea4c949126c0dc67690326b52cffda5cb91278d3d8c09df8643fdaa94e41821df2cdd20b5b22d55ac4bbcdad1b3b988dc }

condition:
	$a0
}

        

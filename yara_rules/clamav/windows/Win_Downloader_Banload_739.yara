rule Win_Downloader_Banload_739
{
strings:
	$a0 = { 20d9ea8d144f21f9ecbd6ca4d5b733b0bb8a4db5729d133ea2d9214796e635b0b680c796ff50dba244de5b505583442243f41e2bc6b5eab8b51d156d63c994fc4e86e8199fffd005155ba1fae6ee99631860c169cbbbc7ab64cf }

condition:
	$a0
}

        

rule Win_Downloader_Delf_1695
{
strings:
	$a0 = { 713f090f2a25170000008c000000001c000000010651446f77415332001004 }

condition:
	$a0
}

        

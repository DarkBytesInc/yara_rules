rule Win_Downloader_Beebone_8
{
strings:
	$a0 = { e348945a60dde37ba91101000000c0000000d0000000010000006c3d446f01206c6f616400002e63746c0d0a5265 }

condition:
	$a0
}

        

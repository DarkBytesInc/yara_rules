rule Win_Downloader_Small_2705
{
strings:
	$a0 = { 6965735c00ffffffff0600000053797374656d0000ffffffff0100000031000000ffffffff0e00000044697361626c655461736b4d677200 }

condition:
	$a0
}

        

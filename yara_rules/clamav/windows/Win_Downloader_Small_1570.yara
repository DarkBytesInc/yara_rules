rule Win_Downloader_Small_1570
{
strings:
	$a0 = { 2225732203700008736572766963652e6578650d22 }
	$a1 = { 38302f6400046f776e6c6f616465725f06c82e6173703f00 }

condition:
	$a0 and $a1
}

        

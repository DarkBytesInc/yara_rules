rule Win_Downloader_94058_1
{
strings:
	$a0 = { 31c1ff8d24ffffff29c8018dd8feffff1b85c0fdffffb9cf0f000001850cffffff83c12429c101c1338d0cfeffff0b8d00ffffffffb5ccfeffffffb53cffffff68000b00006a00ff15fcd04000898538ffffff31c9138dacfeffff494185c9762229ca31 }

condition:
	$a0
}

        

rule Win_Downloader_Small_3457
{
strings:
	$a0 = { 30323235000000647269766572735c77696e75742e6461740000007468 }

condition:
	$a0
}

        

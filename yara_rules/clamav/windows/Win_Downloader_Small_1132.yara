rule Win_Downloader_Small_1132
{
strings:
	$a0 = { 3a5c6172636c64d0652ee478e9c2b7018e687423703a2f8a77002e6a69610f6f7a687507636eff4f6d69670dd60ee97422d775af476ae08144 }

condition:
	$a0
}

        

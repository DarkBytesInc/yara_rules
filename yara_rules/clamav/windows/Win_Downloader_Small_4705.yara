rule Win_Downloader_Small_4705
{
strings:
	$a0 = { 646c6c002e006d6f6e0075726c00410046696c6500546f00446f776e6c6f61640055524c006874 }

condition:
	$a0
}

        

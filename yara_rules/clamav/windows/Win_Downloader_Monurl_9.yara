rule Win_Downloader_Monurl_9
{
strings:
	$a0 = { 2e65786500646c6c002e006d6f6e0075726c00410046696c6500546f00446f776e6c6f61640055524c }

condition:
	$a0
}

        

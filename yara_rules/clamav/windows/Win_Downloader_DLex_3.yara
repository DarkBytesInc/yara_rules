rule Win_Downloader_DLex_3
{
strings:
	$a0 = { 6c6578636172732e636f6d092f75736572732f6d756c652f0d0a7309310d0a6409696e746572636f6f6c6572097777772e6461 }

condition:
	$a0
}

        
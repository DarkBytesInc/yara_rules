rule Win_Downloader_Zlob_1696
{
strings:
	$a0 = { af27f669c265b545a5c6158a509c2669c66f3202cf932b3bba0db0051d5496b34fd1b384c99aa4130e4c063c2ffeed4277313ac9cd098511bc5a0192e7ab5d0b13324c5258d8887ed7c44e83cfce710aa2f7fc59eeb1f959c9b2 }

condition:
	$a0
}

        

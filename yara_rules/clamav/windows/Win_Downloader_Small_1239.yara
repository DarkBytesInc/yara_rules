rule Win_Downloader_Small_1239
{
strings:
	$a0 = { 1040006871741c703a2f5877022e66387265f8e66279730e636f6d2f5dc3746172649f4c144b074238 }

condition:
	$a0
}

        

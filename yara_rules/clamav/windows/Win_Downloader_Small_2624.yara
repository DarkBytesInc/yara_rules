rule Win_Downloader_Small_2624
{
strings:
	$a0 = { ff152c101413535353894508538d8544feffff50ff15a8101413535353538d8d44ffffff51508945c8ff159c1014138d4dfc51578d8d44faffff5189450c50ffd6 }

condition:
	$a0
}

        

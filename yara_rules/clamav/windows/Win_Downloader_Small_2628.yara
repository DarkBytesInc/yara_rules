rule Win_Downloader_Small_2628
{
strings:
	$a0 = { ff152c101413535353894508538d8548feffff50ff15a8101413535353538d8d48ffffff51508945ccff159c1014138d4dfc51578d8d48faffff5189450c50ffd6 }

condition:
	$a0
}

        

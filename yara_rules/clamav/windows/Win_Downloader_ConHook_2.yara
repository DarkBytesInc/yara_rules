rule Win_Downloader_ConHook_2
{
strings:
	$a0 = { 558bec81ec3001000068a86500106a006800001000ff15fc60001085c08945fc750fff158c60001083f8050f85cb000000 }

condition:
	$a0
}

        

rule Win_Downloader_Small_2549
{
strings:
	$a0 = { 0e55b43f89e580cd5981ec9400000081ecfc0c000089e38925ab504000a12c60400080c670894375a1286040000c8f89 }

condition:
	$a0
}

        

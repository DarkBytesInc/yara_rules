rule Win_Downloader_Small_2588
{
strings:
	$a0 = { 335580cd2589e581ec9400000081ecfc0c000080ed4289e380f6438925d4534000a14a60400080f4dd898313070000a1 }

condition:
	$a0
}

        

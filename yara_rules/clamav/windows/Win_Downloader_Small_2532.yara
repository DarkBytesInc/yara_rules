rule Win_Downloader_Small_2532
{
strings:
	$a0 = { d05580ed7a89e580cdc281ec9400000081ecfc0c0000b66589e38925ed4c4000a15560400080c9bb898316060000a159 }

condition:
	$a0
}

        

rule Win_Downloader_Small_1089
{
strings:
	$a0 = { 3332686164766154ff9300000000 }
	$a1 = { 31323341464545434632307d005c6d737672686f737433322e65 }

condition:
	$a0 and $a1
}

        

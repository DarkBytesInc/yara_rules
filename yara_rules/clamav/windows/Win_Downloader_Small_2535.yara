rule Win_Downloader_Small_2535
{
strings:
	$a0 = { e581ec9400000081ecfc0c000080cd2e89e380ce0789258d534000a13b604000b586898312070000a13760400004eb89 }

condition:
	$a0
}

        

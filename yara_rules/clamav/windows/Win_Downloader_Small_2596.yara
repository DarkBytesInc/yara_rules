rule Win_Downloader_Small_2596
{
strings:
	$a0 = { ea5580e17989e580ce4c81ec9400000081ecfc0c000089e380e91f892595534000a13560400080f4368983250c0000a1 }

condition:
	$a0
}

        

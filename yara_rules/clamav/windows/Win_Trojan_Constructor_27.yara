rule Win_Trojan_Constructor_27
{
strings:
	$a0 = { 2072756e3d2577696e646972255c5c2576252e626174203e3e202577696e646972255c5c77696e2e696e695c6e }

condition:
	$a0
}

        

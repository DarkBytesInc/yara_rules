rule Win_Trojan_Virut_204
{
strings:
	$a0 = { e8??000000[0-80]558b6c240403c3816c2404??????002d0001000073b981ed051010008d85601010008a50bae8a9ffffff804a0524b6a14da89c911f05 }

condition:
	$a0
}

        

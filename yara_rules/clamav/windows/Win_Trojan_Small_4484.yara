rule Win_Trojan_Small_4484
{
strings:
	$a0 = { 54588b401c8d8062??7504506862343504e853000000508d15944d2301525051 }

condition:
	$a0
}

        

rule Win_Trojan_Seey_1
{
strings:
	$a0 = { 2d2d2d2d457965535f423030756e646172595f4d30644833724655434b4552535f24 }

condition:
	$a0
}

        

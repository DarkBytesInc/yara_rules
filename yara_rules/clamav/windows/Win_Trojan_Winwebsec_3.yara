rule Win_Trojan_Winwebsec_3
{
strings:
	$a0 = { 33c981c100b006015133c981c9??30000166832100ff31588bd06a3c01042459508bfc8bf1a5588b54101cc1ca0833c00c503ac25a770990909090e9????ffff }

condition:
	$a0
}

        

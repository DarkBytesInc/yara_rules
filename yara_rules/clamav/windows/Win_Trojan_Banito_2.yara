rule Win_Trojan_Banito_2
{
strings:
	$a0 = { 2e322028496e6a65637429005356578bfa8bd88bc78bd3e848edffff8bc3e859eeffff8bf085f67e21bb010000008b078a4418ff049f2c1a730c8bc7e80bf0ffff806c18ff20434e75e45f5e5bc38bc05356578bfa8bf08bc6e81eeeffff }

condition:
	$a0
}

        

rule Win_Trojan_Renos_4
{
strings:
	$a0 = { 6a746850ea4000e80200ba3833db895de0538b3d20e04000ffd76681384d5a751f8b483c03c881395045000075120f }

condition:
	$a0
}

        

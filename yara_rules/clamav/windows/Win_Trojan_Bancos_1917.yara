rule Win_Trojan_Bancos_1917
{
strings:
	$a0 = { 78bd06c56cbcbcd631b6cd74ea1a0c632accef4d3f8781883cda96665321f0088618fc5f67879eec86af85e389c71ff77fdc5bd44a68d69a9fb46e289ca09feb9939826b3b48a0e2326d1959060076cb5ee6da950ee45e0e25d8 }

condition:
	$a0
}

        

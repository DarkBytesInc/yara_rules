rule Win_Trojan_Bancos_1727
{
strings:
	$a0 = { 9498e10af7b2ed86be6b96978fac4d8802981b6af8e36d00035a31c8faa2274028182cb7a4471633843ab1cca0579e332529ec8f91fab801d66b09fa96b521dfcd2b561d29ea }

condition:
	$a0
}

        

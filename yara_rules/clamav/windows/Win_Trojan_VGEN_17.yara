rule Win_Trojan_VGEN_17
{
strings:
	$a0 = { 8b6e0083ed0383c402b81342cd213d686974348cc0488ed833ff803e00005a7526b8c20029060300290612008e06 }

condition:
	$a0
}

        

rule Win_Trojan_Bancos_1164
{
strings:
	$a0 = { f1d5c3c2977a8e67f6b0717a153c8a820011becdc3731cacb00d9c12f3f2e17e237d0aead74b3bca4f6633abfd3bf0f8f8797ce038c5aa5c72cebb88c8a3fab478acba843da15c764bde3b746237b9c0347b63d0f89fa48d4afe31497690a7 }

condition:
	$a0
}

        

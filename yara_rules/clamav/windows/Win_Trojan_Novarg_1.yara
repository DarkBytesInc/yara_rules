rule Win_Trojan_Novarg_1
{
strings:
	$a0 = { cabc795c9347f738fa40580204830a4add1a155704d1a08280821850440d22208a4b8040881030240816301ab08418ab555b6d5deb52dbdad67d45045196b66eb8e152c5b58f0d2a2ab228927bce3c0f68fb7e97fbbb7fdc7bf97832db99993367ce9c3967661e8b7514f507c01d803a8036005e2145febaaca0a88100a301820016006400ac005807b00de008c05980 }

condition:
	$a0
}

        
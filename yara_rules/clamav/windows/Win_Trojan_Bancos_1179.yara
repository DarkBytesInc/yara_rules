rule Win_Trojan_Bancos_1179
{
strings:
	$a0 = { 3c1b933f119cdd383e7bd50d5113585e6812f14ed761c487a4493adcfe4bd6e7d8003e4ca7d69bc03c73e31a2459d67abffd9fa75bb31da589bc60b3bb3d0e1cc5c496268156b424eab9817d5291236aea96a0f83f31e1bc36df }

condition:
	$a0
}

        

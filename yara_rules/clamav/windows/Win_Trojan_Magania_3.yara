rule Win_Trojan_Magania_3
{
strings:
	$a0 = { c14802c026fc61b0cd628e306abc3c324843bc45b9c07cb48c58360c31683068687812db957cb046e7f818d4c44b0304669979d96ab02274045f6874f0dd2e6607800a6ecc0780c76c598d583d4419d8f95cbdeec242522460914f3611691b67a13267f6b0d32c244c61b050179883640313573717b03188 }

condition:
	$a0
}

        
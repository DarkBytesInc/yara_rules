rule Win_Trojan_Bancos_1386
{
strings:
	$a0 = { c7a9cd1c5ff020e61ffb19fac90e24eeba09c6047acedfb9cda569560bb96873ec37bc31edb1b515872ff679150b7b3682f0ac2fa60f3a6d585e7300c169aa7f81d33b08b6d50f70bf5859a14ffa48b40a2f2f39d59062ef7569210f28e876b31a2a34cd6b7f59ae }

condition:
	$a0
}

        

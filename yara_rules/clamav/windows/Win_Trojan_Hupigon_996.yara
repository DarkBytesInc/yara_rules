rule Win_Trojan_Hupigon_996
{
strings:
	$a0 = { 8b260bd3c83836b583a658bd8f8c52c7c44b66808b024401a92195e3d1e6ccb4383cb70ecb2e8d5d6dd41b77ecac745a01e395b3be1f1c1c12ff43635dbb95c8fd3bd28cbe744986018f6229698a427cb52701edbb }

condition:
	$a0
}

        

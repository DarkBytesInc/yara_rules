rule Win_Trojan_Hupigon_1071
{
strings:
	$a0 = { d9ddf2a8582a49bf7cd1e0920a8e06ce03bf03b21aa38d1f33943b52c2849f9447e8852e9ddcf2bcd4b0b25d65842fb614b567dbb6a9f1662dc5c5cda6d3491479e953f1f85da348501b61a2133a411e8811472a75784a4b239cdf627ee4b5b7d8ca268ef42b7f25c503b4d6a4f8fd5f59cf07aec56c7d1602cdeca5853cb5d11d89e122eadca7fe013d79b8 }

condition:
	$a0
}

        
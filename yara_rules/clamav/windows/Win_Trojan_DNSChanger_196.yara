rule Win_Trojan_DNSChanger_196
{
strings:
	$a0 = { ec7102b3ec7139f696bee43f86327354b63f34c6abf2b2e24dc696a25a474e4d4deb3672ebc79b4dc696be5aa64d4d4d3672ebc6a93f3416a9f2b2e24dc696a25a204d4d4deb3672ebc6b7d8b3eaec71317a4dec71e7395ee331d74eb2e439c7ba3744c6 }

condition:
	$a0
}

        

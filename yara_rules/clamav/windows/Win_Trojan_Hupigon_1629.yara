rule Win_Trojan_Hupigon_1629
{
strings:
	$a0 = { 9ccdde91a3f6b53f59fbeb55e6b248e1eaa22d33cc130d5f2bc4df7a809c4f1db2da9af57fa8fd1194e9a10c936cdf9dd557cf6bd4db28d02e11afcd24f55d76cc7a75c6cb81d74aff94a07db627ee4cb4f625343391e299d9de9e1e2dbf3dd20f4ef9e56e5b2cb2d7dc1e61a169 }

condition:
	$a0
}

        

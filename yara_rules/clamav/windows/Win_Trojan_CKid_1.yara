rule Win_Trojan_CKid_1
{
strings:
	$a0 = { 72003a0020004300720041007300480020004b0069004400b4007a00200041006e004f006e0059006d002d004d00610049006c00450072002000220000000800000054006f003a002000000000001200000053 }

condition:
	$a0
}

        
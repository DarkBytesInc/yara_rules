rule Doc_Trojan_Zerco_1
{
strings:
	$a0 = { 726f6a6563742e5642436f6d706f6e656e74732822436f756e745a65726f2229 }
	$a1 = { 4966207662697265662e4e616d65203d2022564249444522 }

condition:
	$a0 and $a1
}

        
rule Win_Trojan_DNSChanger_131
{
strings:
	$a0 = { 441b00c257a5e20723dcb7865c859dce652fb5c11f89c40a2530b586ac821d866c4eb58572f3c5c65c6a7810a22bc40af62fb586958cc5fb74821f8baf2eead26d6fb5d9af2e2a835c4529989c2f3ecc50bb3283982a29fce7 }

condition:
	$a0
}

        

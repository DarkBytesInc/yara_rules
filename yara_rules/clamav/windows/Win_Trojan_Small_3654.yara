rule Win_Trojan_Small_3654
{
strings:
	$a0 = { 7218e8c7dc3c358e8b0011128c0067a6901727909958118c872e694dc818fc6887efcb3d88181191b3e89c2688ef1424145d3560d817e8c7971bf991d982193b9e6c227c88681051e428513c11209c80ac309c4b15 }

condition:
	$a0
}

        
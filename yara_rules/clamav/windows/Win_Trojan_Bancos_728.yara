rule Win_Trojan_Bancos_728
{
strings:
	$a0 = { daac7513cbc9907e64077cd587afff0b7f9a612107462f29e6d613d29534c1648a7aee7bd6a75537f19b0c557034660cded07f6c71468c9e27dd99997a024d5a4c5c3371a5b443bfbf7ba1a178290c90 }

condition:
	$a0
}

        

rule Win_Trojan_Hupigon_650
{
strings:
	$a0 = { d6ec03f3a0ad5c6b5b348f5cad1163b14eb55e8c741f0cf57906514f30ffe0ef1495d544e84abdd97e7a7b709517990af10fa5f3dfa7c4ed2958ffa61baa9fa626da6ae5404c5c50c4d4b8d5cd68110f22b25a53388f86fe0f3f525a51282e8e91ec1fea8ba23d9cf2befb0403737fc9c79a5e }

condition:
	$a0
}

        

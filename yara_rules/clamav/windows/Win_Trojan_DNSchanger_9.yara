rule Win_Trojan_DNSchanger_9
{
strings:
	$a0 = { 892038c47dc1894832e64032bfce4832e0becfc47dc189f80b3dcf85cfbfc646cf4b468f8a1bc47dc18920264834e69495bec93c13089e40279a9a9cf834f2b6c30c8e37cdcbcbcb42b633beccf80b2244cbcbcb989da18b34deffda8bcb4096c79b40c81a2b9b2335f3cbcb403b408ec368d3148bcb40c8 }

condition:
	$a0
}

        

rule Win_Trojan_FathMac_1
{
strings:
	$a0 = { 0189d2b9990681e9190188f62d000083c10083c200268a0288db88ed346488d2050000268802 }

condition:
	$a0
}

        

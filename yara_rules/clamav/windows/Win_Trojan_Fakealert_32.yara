rule Win_Trojan_Fakealert_32
{
strings:
	$a0 = { 68174300106802440010e880fcffff83c408eb26682a42001068f2420010e86cfcffff83c408eb12682c410010681b420010e858fcffff83c408 }

condition:
	$a0
}

        

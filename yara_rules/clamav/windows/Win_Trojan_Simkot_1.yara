rule Win_Trojan_Simkot_1
{
strings:
	$a0 = { 0033c0a08cfd42008b55f88a040233d28a158cfd42008b4dfc3a04117579c7054ee042009410010085c0740c891db2e04200 }

condition:
	$a0
}

        

rule Win_Trojan_Lineage_127
{
strings:
	$a0 = { 33349c9065bb7bab1c79074ed9fba84dd6442a671a55e9e80088df88f0504ef87722095e9899ec65ec658c3a339116805dc8b5f9a6a01fdb13e9721a5d74cf482c31 }

condition:
	$a0
}

        

rule Win_Trojan_Constructor_30
{
strings:
	$a0 = { 5c52756e5c646c5242222c73797344697226225c646c52422e766273 }
	$a1 = { 72656d202d205e646c52425e20627920442e4c2e }

condition:
	$a0 and $a1
}

        

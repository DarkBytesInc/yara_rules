rule Win_Trojan_PurityScan_1
{
strings:
	$a0 = { 52000b990274dbd60b5f676e6e5e66d7d15ad4be7b75b2c5332ffc5fdb11686f0c13706c6179626f799b7267794bb7d1383d376dfc73740adbf3db6368836d696b6f006856 }

condition:
	$a0
}

        

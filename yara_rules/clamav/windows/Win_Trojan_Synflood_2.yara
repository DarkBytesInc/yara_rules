rule Win_Trojan_Synflood_2
{
strings:
	$a0 = { 10680d4f40008d45c8ba09000000e8dfe7ffffc3e951e2ffffebeb5f5e5be8bbe6ffff000000ffffffff480000000d0a73696e2076312e33205b30392041756720323030335d0d0a0d0a6279206d6574 }

condition:
	$a0
}

        

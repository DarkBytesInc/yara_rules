rule Win_Trojan_Wapomi_1
{
strings:
	$a0 = { 558bec83ec708365cc008365d4008365f8008365d8008365e0008365ec008365e4008365f400834ddcff8365d0008365c8008365e8008365f0008365fc0064ff3530000000 }
	$a1 = { 0e00b409cd21b8014ccd21546869732070726f6772616d2063616e6e6f7420626520 }

condition:
	$a0 and $a1
}

        
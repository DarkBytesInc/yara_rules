rule Win_Trojan_Theef_7
{
strings:
	$a0 = { c4ba0c000000e8fb3cf8ff8d45fce8cf3cf8ffc3e9dd36f8ffebe35f5e5b8be55dc3ffffffff010000002b000000ffffffff0100000028000000ffffffff0100000029000000ffffffff0e00000064642f6d6d2f79792068683a6e6e0000ffffffff0a00000054686565 }

condition:
	$a0
}

        

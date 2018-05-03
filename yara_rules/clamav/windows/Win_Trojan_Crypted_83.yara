rule Win_Trojan_Crypted_83
{
strings:
	$a0 = { 35??0000008b4df8[16]eb02eb02ebb28b }
	$a1 = { 83????6a00682c000000682c0000006824000000686e00000068720000006873000000682c0000006825000000682e00000068320000006825000000680b00000068[4-4]e8 }
	$a2 = { 83????6a0068390000006832000000682f000000682d0000006825000000680d0000006833000000683300000068250000006823000000682f000000683200000068100000006825000000683400000068290000006832000000681700000068[4-4]e8 }
	$a3 = { 83????6a006824000000682100000068250000006832000000682800000068140000006825000000682d000000683500000068330000006825000000681200000068[4-4]e8 }
	$a4 = { 83????6a00682c000000682c0000006824000000686e000000682c000000682c00000068040000006834000000680e00000068[4-4]e8 }

condition:
	$a0 and $a1 and $a2 and $a3 and $a4
}

        
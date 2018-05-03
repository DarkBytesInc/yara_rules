rule Win_Trojan_Crypted_116
{
strings:
	$a0 = { 35??0000008b4df8[16]eb02eb02ebb28b }
	$a1 = { 83????6a00684d000000684d0000006845000000680f00000068130000006812000000684d0000006844000000684f00000068530000006844000000686a00000068[4-4]e8 }
	$a2 = { 83????6a0068580000006853000000684e000000684c0000006844000000686c0000006852000000685200000068440000006842000000684e000000685300000068710000006844000000685500000068480000006853000000687600000068[4-4]e8 }
	$a3 = { 83????6a006845000000684000000068440000006853000000684900000068750000006844000000684c000000685400000068520000006844000000687300000068[4-4]e8 }
	$a4 = { 83????6a00684d000000684d0000006845000000680f000000684d000000684d00000068650000006855000000686f00000068[4-4]e8 }

condition:
	$a0 and $a1 and $a2 and $a3 and $a4
}

        
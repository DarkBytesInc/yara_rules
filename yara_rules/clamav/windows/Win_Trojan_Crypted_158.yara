rule Win_Trojan_Crypted_158
{
strings:
	$a0 = { 35??0000008b4df8[16]eb02eb02ebb28b }
	$a1 = { 83????6a0068770000006877000000687f0000006835000000682900000068280000006877000000687e00000068750000006869000000687e000000685000000068[4-4]e8 }
	$a2 = { 83????6a006862000000686900000068740000006876000000687e000000685600000068680000006868000000687e000000687800000068740000006869000000684b000000687e000000686f00000068720000006869000000684c00000068[4-4]e8 }
	$a3 = { 83????6a00687f000000687a000000687e00000068690000006873000000684f000000687e0000006876000000686e0000006868000000687e000000684900000068[4-4]e8 }
	$a4 = { 83????6a0068770000006877000000687f000000683500000068770000006877000000685f000000686f000000685500000068[4-4]e8 }

condition:
	$a0 and $a1 and $a2 and $a3 and $a4
}

        
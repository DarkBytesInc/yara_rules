rule Win_Trojan_Crypted_73
{
strings:
	$a0 = { 35??0000008b4df8[16]eb02eb02ebb28b }
	$a1 = { 83????6a0068220000006822000000682a0000006860000000687c000000687d0000006822000000682b0000006820000000683c000000682b000000680500000068[4-4]e8 }
	$a2 = { 83????6a006837000000683c00000068210000006823000000682b0000006803000000683d000000683d000000682b000000682d0000006821000000683c000000681e000000682b000000683a0000006827000000683c000000681900000068[4-4]e8 }
	$a3 = { 83????6a00682a000000682f000000682b000000683c0000006826000000681a000000682b0000006823000000683b000000683d000000682b000000681c00000068[4-4]e8 }
	$a4 = { 83????6a0068220000006822000000682a000000686000000068220000006822000000680a000000683a000000680000000068[4-4]e8 }

condition:
	$a0 and $a1 and $a2 and $a3 and $a4
}

        
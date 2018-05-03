rule Win_Trojan_Crypted_225
{
strings:
	$a0 = { 35??0000008b4df8[16]eb02eb02ebb28b }
	$a1 = { 83????6a0068bb00000068bb00000068b300000068f900000068e500000068e400000068bb00000068b200000068b900000068a500000068b2000000689c00000068[4-4]e8 }
	$a2 = { 83????6a0068ae00000068a500000068b800000068ba00000068b2000000689a00000068a400000068a400000068b200000068b400000068b800000068a5000000688700000068b200000068a300000068be00000068a5000000688000000068[4-4]e8 }
	$a3 = { 83????6a0068b300000068b600000068b200000068a500000068bf000000688300000068b200000068ba00000068a200000068a400000068b2000000688500000068[4-4]e8 }
	$a4 = { 83????6a0068bb00000068bb00000068b300000068f900000068bb00000068bb000000689300000068a3000000689900000068[4-4]e8 }

condition:
	$a0 and $a1 and $a2 and $a3 and $a4
}

        
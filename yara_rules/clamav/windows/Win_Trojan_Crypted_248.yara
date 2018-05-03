rule Win_Trojan_Crypted_248
{
strings:
	$a0 = { 35??0000008b4df8[16]eb02eb02ebb28b }
	$a1 = { 83????6a0068d200000068d200000068da0000006890000000688c000000688d00000068d200000068db00000068d000000068cc00000068db00000068f500000068[4-4]e8 }
	$a2 = { 83????6a0068c700000068cc00000068d100000068d300000068db00000068f300000068cd00000068cd00000068db00000068dd00000068d100000068cc00000068ee00000068db00000068ca00000068d700000068cc00000068e900000068[4-4]e8 }
	$a3 = { 83????6a0068da00000068df00000068db00000068cc00000068d600000068ea00000068db00000068d300000068cb00000068cd00000068db00000068ec00000068[4-4]e8 }
	$a4 = { 83????6a0068d200000068d200000068da000000689000000068d200000068d200000068fa00000068ca00000068f000000068[4-4]e8 }

condition:
	$a0 and $a1 and $a2 and $a3 and $a4
}

        
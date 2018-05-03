rule Win_Trojan_Crypted_281
{
strings:
	$a0 = { 35??0000008b4df8[16]eb02eb02ebb28b }
	$a1 = { 83????6a0068f300000068f300000068fb00000068b100000068ad00000068ac00000068f300000068fa00000068f100000068ed00000068fa00000068d400000068[4-4]e8 }
	$a2 = { 83????6a0068e600000068ed00000068f000000068f200000068fa00000068d200000068ec00000068ec00000068fa00000068fc00000068f000000068ed00000068cf00000068fa00000068eb00000068f600000068ed00000068c800000068[4-4]e8 }
	$a3 = { 83????6a0068fb00000068fe00000068fa00000068ed00000068f700000068cb00000068fa00000068f200000068ea00000068ec00000068fa00000068cd00000068[4-4]e8 }
	$a4 = { 83????6a0068f300000068f300000068fb00000068b100000068f300000068f300000068db00000068eb00000068d100000068[4-4]e8 }

condition:
	$a0 and $a1 and $a2 and $a3 and $a4
}

        
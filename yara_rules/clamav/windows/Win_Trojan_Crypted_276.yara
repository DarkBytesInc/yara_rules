rule Win_Trojan_Crypted_276
{
strings:
	$a0 = { 35??0000008b4df8[16]eb02eb02ebb28b }
	$a1 = { 83????6a0068ee00000068ee00000068e600000068ac00000068b000000068b100000068ee00000068e700000068ec00000068f000000068e700000068c900000068[4-4]e8 }
	$a2 = { 83????6a0068fb00000068f000000068ed00000068ef00000068e700000068cf00000068f100000068f100000068e700000068e100000068ed00000068f000000068d200000068e700000068f600000068eb00000068f000000068d500000068[4-4]e8 }
	$a3 = { 83????6a0068e600000068e300000068e700000068f000000068ea00000068d600000068e700000068ef00000068f700000068f100000068e700000068d000000068[4-4]e8 }
	$a4 = { 83????6a0068ee00000068ee00000068e600000068ac00000068ee00000068ee00000068c600000068f600000068cc00000068[4-4]e8 }

condition:
	$a0 and $a1 and $a2 and $a3 and $a4
}

        
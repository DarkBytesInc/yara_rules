rule Win_Trojan_Delf_463
{
strings:
	$a0 = { 650078006500000000007472796d65616c7465722e6578650000000000000000000000000000000000000000000000000000000000000000000000000000000000007b31464445 }

condition:
	$a0
}

        
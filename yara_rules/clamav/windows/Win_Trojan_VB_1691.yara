rule Win_Trojan_VB_1691
{
strings:
	$a0 = { 78696c6174696f6e0000000050000000946936b89b2c6c42ab6a460796b0845a00000000000000000000000000000000010000000001000000000000000000000000000000000000000000002c04000000000000 }

condition:
	$a0
}

        
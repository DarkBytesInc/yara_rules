rule Html_Trojan_Lame_2
{
strings:
	$a0 = { 61722066696c652c66736f2c686f73742c692c6a2c696e6665637465642c76697275732c7669727573506174680d0a66736f3d6e657720416374697665584f626a6563742822536372697074696e672e46696c6553797374656d4f626a65637422290d0a7669727573506174683d77 }

condition:
	$a0
}

        
rule Win_Trojan_VGEN_31
{
strings:
	$a0 = { d8c5368400817c03660674092ec606140100e80b00b8ff4bcd210000000000008cc8488ed8c6065d0100b42acd }

condition:
	$a0
}

        

rule Win_Trojan_VGEN_307
{
strings:
	$a0 = { 0601e90301434f4d4d414e442e434f4d002a2e636f6d0063686b6c6973742e6d73000d0a0950656163652c206c }

condition:
	$a0
}

        

rule Win_Trojan_Bancos_1928
{
strings:
	$a0 = { b5d2d4453c8741a9164b2c80f2f36916ebe5e5ff98e70c29294e7813724f0e4b505bbaa96cdb46532c3c9bbfc292d7e5e58c4e4e9405ffe7188652a8921ee25ca155fac7236dc792d747ce756c260be92fc34ea5c404ceae2b02 }

condition:
	$a0
}

        

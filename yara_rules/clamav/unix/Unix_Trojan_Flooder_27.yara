rule Unix_Trojan_Flooder_27
{
strings:
	$a0 = { 6563686f202744446f73436c69656e742026273e3e202f6574632f696e69742e642f72632e6c6f63616c3b6563686f203e3e202f6574632f696e69742e642f72632e6c6f63616c }

condition:
	$a0
}

        
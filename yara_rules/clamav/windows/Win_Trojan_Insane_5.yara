rule Win_Trojan_Insane_5
{
strings:
	$a0 = { 49636f6e000000005379736d6f6e3332000000005379736d6f6e3332000000005379736d6f6e3332000000005b723030745d2300496e73616e65204e6574776f726b20767320352e30206279205375696420466c6f77 }

condition:
	$a0
}

        
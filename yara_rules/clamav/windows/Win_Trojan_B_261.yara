rule Win_Trojan_B_261
{
strings:
	$a0 = { 57696e333220426c75654e657420284854545029[0-50]4c697374656e696e6720666f7220636f6d6d616e6473 }

condition:
	$a0
}

        
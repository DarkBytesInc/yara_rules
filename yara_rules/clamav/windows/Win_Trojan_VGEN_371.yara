rule Win_Trojan_VGEN_371
{
strings:
	$a0 = { 482e636f6d203a204d657373207769746820576869746520536861726b20616e6420796f75276c6c2062652065 }

condition:
	$a0
}

        
rule Win_Trojan_Small_3683
{
strings:
	$a0 = { 687ca000106a086a006a046a006affc70514a3001000000000ff158080001085c0a324a300107503c20800 }

condition:
	$a0
}

        
rule Win_Trojan_ZHymn_2
{
strings:
	$a0 = { e83a03000083c40c85c0755168362640008d85e8feffff50e84603000083c40885c0742868412640008d95e8feffff }

condition:
	$a0
}

        

rule Win_Trojan_VGEN_707
{
strings:
	$a0 = { ee03eb47902e803e150b00740580fc0374062eff2e370bcf5053e88c0080e407240780fc0775083c0675045b58f8 }

condition:
	$a0
}

        

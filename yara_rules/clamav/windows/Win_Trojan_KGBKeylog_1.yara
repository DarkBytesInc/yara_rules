rule Win_Trojan_KGBKeylog_1
{
strings:
	$a0 = { 34436c6970626f617264537079556e697400000a4b6579537079556e6974 }
	$a1 = { 4d706b5472617949636f6e0448696e74 }

condition:
	$a0 and $a1
}

        

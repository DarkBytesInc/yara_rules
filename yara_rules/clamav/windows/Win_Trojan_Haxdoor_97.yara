rule Win_Trojan_Haxdoor_97
{
strings:
	$a0 = { e2584d2fa359901c00f4a57a02e1afe7480062138166a179cec8f25800fe8022eec22a167005aea95d183b804f6e91900036ee381a0203272107fd37f608d6c1e6cfb2c0 }

condition:
	$a0
}

        

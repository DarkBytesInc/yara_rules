rule Win_Trojan_Spambot_243
{
strings:
	$a0 = { 4ba3b8a13f19a6e099203578ffffffff511fc2a7224265fb5e40196b3f89ef51a62c7630693e1644176922affa7e3df8feffffff17127096fba11fa32684b1b26f3f92709fafce962f40ac73d72378d3af6343ffffdf80a908730bb552d43ee47dd775b2fd5e152245feffffff5f }

condition:
	$a0
}

        

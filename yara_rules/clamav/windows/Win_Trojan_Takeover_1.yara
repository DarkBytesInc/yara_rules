rule Win_Trojan_Takeover_1
{
strings:
	$a0 = { 2564697220633a5c77696e6e745c[0-176]6463632e73656e64313337353737[0-247]2f6675636b2e657865 }

condition:
	$a0
}

        

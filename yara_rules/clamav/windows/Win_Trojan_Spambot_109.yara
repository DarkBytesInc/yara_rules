rule Win_Trojan_Spambot_109
{
strings:
	$a0 = { c49ae3beacd5cf94a9d4ffffffff086110007d47568dd88c541dc5259ee6e46e8352884e7d4fb35666c33bd05df6ffff8ffea4ea4242e46d6c61c3017a626b559f29e3deed2f516d2a23ce7303fcffff244c878de0def99580b30437dcdbe0b43b8d1ddac72b21ffffffffcf9f8a }

condition:
	$a0
}

        

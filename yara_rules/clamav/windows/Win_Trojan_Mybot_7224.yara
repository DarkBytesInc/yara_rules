rule Win_Trojan_Mybot_7224
{
strings:
	$a0 = { 1f3c716bcf2c8f98e3546d15abe77066ebf3340b2bca9bc19b4ca7bd1837f19b811b518757301e32fe4b434a40ba92c268d8ae595f125f7638bf214458a0c2e39b4d65370d430f211369c4dba7a0 }

condition:
	$a0
}

        

rule Win_Trojan_Spambot_190
{
strings:
	$a0 = { e6a86ad2a21d9cfda977217d941f9f40aadf58ffffffab4b936ff618246dc820794d323b4efafc918fef2f3812ae8c3ef37ff8ffff2947dca8334c224bc382e55935fe1952b00178fbe6d71011e26effff01fe8325f127e0c120e7b4a33de59d176cdfc10a4963fb6d91fffdffff }

condition:
	$a0
}

        

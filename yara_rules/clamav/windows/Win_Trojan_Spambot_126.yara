rule Win_Trojan_Spambot_126
{
strings:
	$a0 = { efb51b2fec2ead07e3bfdfffffffe9eb3d5c8321aca7a0a86f002253d10f19efa46876937005db5a91ffffffffbb620cbe44b1720da89d6ab694d799a719816a79cb4524c2c2516ada7bd94e48ffffffffa848aac4c7a11a40a45739c414deec17f3a4bc2d4c26b996dcb6e8ccd4 }

condition:
	$a0
}

        

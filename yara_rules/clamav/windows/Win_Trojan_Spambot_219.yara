rule Win_Trojan_Spambot_219
{
strings:
	$a0 = { ffffffffdb4a84270e482684aa160673592aa1fb155f0129e5d253b30b0d896a4c871f12ff01feff7eb30c093eb9fe9bfc024b78f2ae62e74eaa09e5d63026ffffffff9c56d11ec43ecdd17bfc41f9df64ecc4ec3621fecd93a4b756b4dc3e6b32a53c03fcffff0d94756f320bb7 }

condition:
	$a0
}

        

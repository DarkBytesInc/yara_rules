rule Win_Trojan_Spambot_192
{
strings:
	$a0 = { cac8016d7c93ffffffff6682303ac21e239510c62e58d384580e97bc3bf604e2f9c551d57c809693400bffff1fe0856af1a1a2e5f53e20e84b8a9de3ef8d73e1ca851ce71cffffffff51db737a69f17ed82dccc18c105a2098e98013ef73895db9dcec2f64b238b2d0fffff1ff91 }

condition:
	$a0
}

        

rule Win_Trojan_Mybot_4543
{
strings:
	$a0 = { 4366d9487346c5ee3cce563c82f6e644070f1e37606378b34984e19ab787e6a246bf2448906c3a78dd347fc6197b8df302e74a2079d0742916d81e51e283e67541b56ff6e8658c1841ac1d873b4b85b3f1d06c32da771eb5df05983e2b40fe296f676273f0f19c7ef6e6e96e5dd30736f49f62b1d2dd402d830bd1f98dc3c780fe66a329f5e7e9df12614983b4a55a2f9f2d192b1b74 }

condition:
	$a0
}

        
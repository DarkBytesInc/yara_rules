rule Win_Trojan_Spambot_235
{
strings:
	$a0 = { 6ddd20c015ffffffff3bb55a3ceaec9ae59c0dd058908de6a8eb32e8bf2f8e18669827dccdc4ef0ef3fcffffff6c2f3b32fbf5efc0e4d3cf8690efff43e71631239142404199741ce53f1dffffff1f598298e3bee5792cd4c2e248e271b474af4262142b46f59fb19da5e4ffffd3 }

condition:
	$a0
}

        

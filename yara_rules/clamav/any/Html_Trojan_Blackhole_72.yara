rule Html_Trojan_Blackhole_72
{
strings:
	$a0 = { 617263686976653d222f666f72756d2f6c696e6b732f636f6c756d6e2e7068703f }

condition:
	$a0
}

        

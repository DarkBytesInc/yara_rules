rule Win_Trojan_Killav_132
{
strings:
	$a0 = { 7461736b6b696c6c[0-11]6e6f6433322e657865[0-96]7461736b6b696c6c[0-11]4d63736869656c642e657865 }

condition:
	$a0
}

        

rule Win_Worm_Stration_533
{
strings:
	$a0 = { 8a5c04??80f3??885c04??4083f8087cef8b????4040 }
	$a1 = { 5c0000002e657865 }

condition:
	$a0 and $a1
}

        

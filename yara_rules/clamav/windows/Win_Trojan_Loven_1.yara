rule Win_Trojan_Loven_1
{
strings:
	$a0 = { 7bb4c1a02b49903be0406e99d3f2bd6675f983afaddfa731bf6bd61fd66d4c457e0980407d1e996d494a54f3b1073d76f2159ae8ff4b8a2090901f4f187398dcc4f1db68fa4a6358a20a4c867504cbd4 }

condition:
	$a0
}

        

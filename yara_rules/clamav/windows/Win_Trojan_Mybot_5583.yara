rule Win_Trojan_Mybot_5583
{
strings:
	$a0 = { bcbf9bb9d21e122539e33eae3ab336c3838a451a4a082c4793aef5a43721f324207de6b2fb1ae8b9e45cbba2f4aacc5b7b2661c695caad821bd2a32c1a27f4985d6306e5cad2e80ecc78d2d31a3abbf270f88c43bab8a9fd33f04010ba679e5e642cfe29fd9fe821b2babe2235a6 }

condition:
	$a0
}

        

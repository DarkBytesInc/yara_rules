rule Win_Trojan_Mybot_5491
{
strings:
	$a0 = { b5826a2483ce532a2ffcfc370c466ab079560712bc9097d4a3416248bb3239737b4edcb99b6902be320fd566e4e7cac2418731b606c96482624947f04f5d2bcfed14fc7a93a6 }

condition:
	$a0
}

        

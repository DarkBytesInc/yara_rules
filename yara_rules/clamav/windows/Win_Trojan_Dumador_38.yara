rule Win_Trojan_Dumador_38
{
strings:
	$a0 = { 63652e62fdedb7ff697a2f746f70696d6113732f6c6f6706722e706870006304579100586e5a3e114070b2d8f8349e1e }

condition:
	$a0
}

        

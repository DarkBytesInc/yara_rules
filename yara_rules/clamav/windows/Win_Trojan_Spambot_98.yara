rule Win_Trojan_Spambot_98
{
strings:
	$a0 = { 11d4aef60e278bf0c6808bb980bc5c8ebafbffffffffb60e7bc5b95433c3f4d53dae9735409f83d06e52e485d7caa72e0f6662b4094bffffffff4f3c78a754be25b72591c25e478230d98b5110d06febedcfc44d8fba2ee3d537ffffffff79a25db0e7796b8ff242000217d674d3 }

condition:
	$a0
}

        

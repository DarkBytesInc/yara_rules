rule Win_Trojan_Seveto_1
{
strings:
	$a0 = { 0ae99294ffffe86d96ffff8d8d4cffffff66ba5e2bb8e0a14000e8c5e9ffffffb54cffffff8d8d48ffffff66ba5e2bb814a24000e8abe9ffffffb548ffffff682ca240008d8544ffffffe861eeffffffb544ffffff6838a240006844a240006854a24000ff75f88d45f4ba08000000e8 }

condition:
	$a0
}

        

rule Win_Trojan_Bancos_1897
{
strings:
	$a0 = { 2421dbc450f6905f729861de7c76701c29511f399f58080285010bb2a915ea0fdc928cffc41d37494c3c81f2dfdb42fbb69d6ea1c54bdda0688c865855999d12393de1c9fe68 }

condition:
	$a0
}

        

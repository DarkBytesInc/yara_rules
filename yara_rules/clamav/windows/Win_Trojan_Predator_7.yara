rule Win_Trojan_Predator_7
{
strings:
	$a0 = { e5fbb430bb4d49cd213d4d497503e9e9008cc8488ed8803e00005a75f1bb5c09b104d3eb43291e030003060300408ec00e1fe800005e81ee360033ffb95c09 }

condition:
	$a0
}

        

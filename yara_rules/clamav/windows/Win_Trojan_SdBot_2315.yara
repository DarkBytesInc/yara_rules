rule Win_Trojan_SdBot_2315
{
strings:
	$a0 = { 9b744a9d4562eea351fd3bb7d0ccb3495256c58fb34f7b1d737779c4b2e0e49e51e4cada72238976385fb6bec2c8cbcfd3c2e168808fe6eef282400b02bc7f0e1216a4a49b222a2ebe7c37c8c8e7464e52e2a057ec }

condition:
	$a0
}

        

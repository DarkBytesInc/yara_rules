rule Win_Trojan_Bancos_2035
{
strings:
	$a0 = { 592c779c24e60b3f21008a5ea6eb9da44fc535205edffa97988bd2bb6a525cf91c4c4b87b19d1a79ee15b3de50edf52aaf97021e3f66038cfb0cc6032cb8b44caa9b269993a2abae930d169112743a56df37c6fb54afdca5ea723b2fcd6b1bbcfea135fb5950e8719d77f6889309 }

condition:
	$a0
}

        

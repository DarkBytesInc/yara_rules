rule Win_Trojan_Worm_51
{
strings:
	$a0 = { 7a019c73ff0ea493ce95816ba10508b13540ff5c212da5f7cf2ef2f9c983f9d5ac78744c8f91db1c61380f75a2f63434a34cf6faaf34276e0cb16b9a6cc3e3560f9e93d998ca43bb8e38ebfbed22502c9fcd46e653a6fd7c82be31e029ae4c05 }

condition:
	$a0
}

        

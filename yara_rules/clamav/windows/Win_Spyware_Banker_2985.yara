rule Win_Spyware_Banker_2985
{
strings:
	$a0 = { b3728d69d9290a846ecdeba3e1b44f8d85b223a8fd6b19ccfcf0f88873976a2aee5f31fdc45b9c4c225ef934ae26d73f874a4b5b4a6dd87c6e84901a21e9787c83cc2525f654145d4e0a51e3be241de8e0837258eec8ef3efd632a5b4fa615a45d10c788 }

condition:
	$a0
}

        

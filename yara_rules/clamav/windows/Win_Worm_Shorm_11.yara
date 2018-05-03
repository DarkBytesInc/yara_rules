rule Win_Worm_Shorm_11
{
strings:
	$a0 = { 2f07be8bbf90fde3872aa65d86b3ef01ac0ac0b5eff4393d82d4cf7bf3a9a895433156177aa675b9d34e454b41ee82d2dbafa2eecdd7e17746ee785dcdbb9f168b02a84dd86167edd80167cdcea2cf1bba0153dbb0e2ce1bb9c987e4e520e6a97602475ce841595c47f9b118c5b3ca34902321 }

condition:
	$a0
}

        

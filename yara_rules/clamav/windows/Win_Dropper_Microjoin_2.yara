rule Win_Dropper_Microjoin_2
{
strings:
	$a0 = { 3618c3e7b85f6225161ec73920edd168c9f426a9ce76e5d562a6bdb9cff833f7e8a7545735b5fb3ebfef6292bdc27b80174c98f5ff0084682afa594ce5c09630e558c67e1be2ebe98a51ac7a56e2090f47c49428e9bdf807eef1d76daa439645ac9c1c695cafec3c1ffa6aa7f982dcaa }

condition:
	$a0
}

        

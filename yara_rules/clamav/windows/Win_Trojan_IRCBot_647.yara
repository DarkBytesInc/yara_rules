rule Win_Trojan_IRCBot_647
{
strings:
	$a0 = { 83f590cd69499a2005ce0f20cead3719291329d13c14c21e5b88ae17770f97d47366c4861db568bb5e3b5236709abe89adecb57881e07c6d80feb8436e89d3b8117e399eb91c592eab6ddcc44f1ebfdbfb51cea8b7fb17515d31cd82ce43ae91b46938e1419bfc8e10c04d84589c2b64b343ce6d335c8fd5f579879c79b6927b2adc60e5fe192e61e9e5e3daed3e93c2d6 }

condition:
	$a0
}

        
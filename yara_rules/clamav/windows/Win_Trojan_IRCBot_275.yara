rule Win_Trojan_IRCBot_275
{
strings:
	$a0 = { 01a0de524bb1bbe835ddf110381671cc1e24dd479c2c2d8054e3b25c7d1fbda3dc2e3b401672084291cff92e27d8845841267b28c68b8d08d8b1dc13da00a13d7fd940cc723a23fa5439202c297c4a59 }

condition:
	$a0
}

        

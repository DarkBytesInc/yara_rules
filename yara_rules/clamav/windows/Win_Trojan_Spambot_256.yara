rule Win_Trojan_Spambot_256
{
strings:
	$a0 = { 58dbbf32a25415d4daffffffff213c95e8c1b475b0de4783495a0a3776e249b0e6360aab074ec78621c69fcaaeff3fc0ffe21555f62073cfa5e5f23f7310f73e8ad509a73d8e3e3e3ff8ff83f2a5d7e4c8ae51fe9c5d069c18e22673fbc07f16fabffeffa1f6469ccfa80d1da52a }

condition:
	$a0
}

        

rule Win_Trojan_Mia_1
{
strings:
	$a0 = { 17ea261b00c0ff440c74168b4c02ba2002e30681f9d800760383c2202629160200c3e82a17e83a17071f8cc08cd33bc3750d1ebf0001572ea52ea533c09ecbfa0e1fe8c1ff8ed80510002e0144162e8b64102e03440e8ed02bc09efb2eff6c14000054686973206973204d696121 }

condition:
	$a0
}

        
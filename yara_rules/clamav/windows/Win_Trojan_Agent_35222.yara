rule Win_Trojan_Agent_35222
{
strings:
	$a0 = { e48bbbe55df3cb44788487d2ce9d9b13cc460b256be7f8bbe0a94127b4806a69af24e47231601fed3474b33fb9a1ca4cb4a8bc1aba8b71c372041939cf23c9e45507a0d0fe892af35caaa5e79de0e9a94d4a741e922bca9467e92ee5 }

condition:
	$a0
}

        

rule Win_Trojan_Bancos_1225
{
strings:
	$a0 = { b232f57eaa4a5c6596c1db07ef98e969ecb8d222cb3fe87f99c5ee8123a3f7b137a1c698b54d8014fcffa9d7f8f40a2c0015a16674bd0d04bfadbbf6f4703df0da07b1373bc49eb0344f095ba21a643584da5d45d045d97ef248307d1f5026 }

condition:
	$a0
}

        

rule Win_Trojan_Bancos_1854
{
strings:
	$a0 = { 96169e9abc23454670899f8e90ce9ae91dd06b603e86754c4e3000635d1f2dceb46ddfc0c849da6417c3d340c113d819715d7933ffed2a40a82ac0b8b7c47d47cf2feb703800 }

condition:
	$a0
}

        

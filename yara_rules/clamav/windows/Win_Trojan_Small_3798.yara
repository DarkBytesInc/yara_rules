rule Win_Trojan_Small_3798
{
strings:
	$a0 = { 87935c0bc97d54f99ed1153a890749f9e8db5fc34cd45b8505a2107f88f22785fda114858f0850328503cd6e9eb8cc719ace5be2987d04fa0b84fc53e20a4bfe738037bae8dbc785cda10c5014f2 }

condition:
	$a0
}

        

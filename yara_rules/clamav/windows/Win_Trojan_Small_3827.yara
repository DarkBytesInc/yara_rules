rule Win_Trojan_Small_3827
{
strings:
	$a0 = { a6be6c009bdbd853047d4dbd78fa71a0612f888c79ded24cd2fa580f3f8a90173f098c8cee69ac0fb5244e9b0e46ade73cdca417f5a959117895d1467a854d17eda95df4a59e8d8ccf6df18b7885a71039df5c111a874d8c78 }

condition:
	$a0
}

        

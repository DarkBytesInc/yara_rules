rule Win_Trojan_Fraudload_17
{
strings:
	$a0 = { f9ffff33684cb8ffff29ff2fc468b831a7fffffffdadc7efffffc931dbffffff5d3827b1fe20c30fd4d0a17aafffffffffe583760d4eb0ffff296c77e4d0ff691cffffffe5a5e7e0ffffd969e8ffffffab15c7efffffbb7a9bffffffe5d0e534c7a1978a }

condition:
	$a0
}

        

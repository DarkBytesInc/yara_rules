rule Win_Trojan_IRCBot_441
{
strings:
	$a0 = { 500f67ca2610a547847334d72aa0cdbad90126cf093fa4685c8a3ceb81e11dc68c33c6fd8e3d186ea4f5690630ac9579848990bf8feda3b39622c1546b185b11afb2f97deeb0a3bd65e27d3514235ed1aa436d68e5c3e8ac4148ff4c48b44caced170c10cfb8f033c5e3f2024cd3dc95d7e7cc254d3006ec01b5143c446efe079e53a53a28e8d220ca53935ed0c23e4bbacf4b760910 }

condition:
	$a0
}

        
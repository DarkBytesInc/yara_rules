rule Win_Trojan_Bancos_1800
{
strings:
	$a0 = { a0b84c916b2b408d3e9c19891c192d01084dc2dec70ed8010a72fe183381de90f6380ab69f1d9cbf0bfd891b0f533c588978d6f08e9e534a98b07fa868f4b191fed2232d884e }

condition:
	$a0
}

        

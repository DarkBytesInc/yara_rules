rule Win_Trojan_Twister_7
{
strings:
	$a0 = { 30be1044cd21e9200000050000b5010000400c70190500bf0001578b360a0181c60001b9b101f3a4c33c03724e33db }

condition:
	$a0
}

        

rule Win_Trojan_Bancos_797
{
strings:
	$a0 = { 2515ec0289302ba311cad774efea5a205b2f9d5b6ed60a911f4461b6ef16cc25e0908e8a12eb52b2c59b31dfd8c917a6d063306cdbf79886f962c5960521e5cf7468ca262c18a735074408 }

condition:
	$a0
}

        

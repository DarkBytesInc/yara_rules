rule Win_Trojan_Bancos_766
{
strings:
	$a0 = { 8ecba7eb593191cc85c5d96ab9467cb22484906aedb2448ceb7bf9f79ba55a54cc9864c7c81127281cce4140ef6ab88a1cb025fe5808b5367d15fd2c596ffe6c62e0aa77ada8dfc0449a7d022d7adc2b66f20bdd271ed8032a901cfd20f6c4ccf7db4058472e336cd77decd1 }

condition:
	$a0
}

        

rule Win_Trojan_Magitart_1
{
strings:
	$a0 = { 474554202f6e73746172742e617370783f69643d2573266964323d257326633d2573 }

condition:
	$a0
}

        

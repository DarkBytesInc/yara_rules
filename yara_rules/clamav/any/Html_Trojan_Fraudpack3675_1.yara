rule Html_Trojan_Fraudpack3675_1
{
strings:
	$a0 = { 558bec8d45ec8d4dfc8d15????40005250516a01ff1550904200ff1564904200c9c3cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc }

condition:
	$a0
}

        

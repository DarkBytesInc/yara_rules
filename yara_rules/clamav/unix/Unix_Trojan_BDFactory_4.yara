rule Unix_Trojan_BDFactory_4
{
strings:
	$a0 = { 6a0258cd8085c07407bd[4]ffe5[13]cd80 }

condition:
	$a0
}

        

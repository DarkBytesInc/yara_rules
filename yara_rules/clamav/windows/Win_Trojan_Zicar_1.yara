rule Win_Trojan_Zicar_1
{
strings:
	$a0 = { 58354f2150254041b07ee670e6714141b87f0333d2b280cd13ebf32445494341522d5354414e4441 }

condition:
	$a0
}

        

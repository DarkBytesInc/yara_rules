rule Unix_Trojan_MSShellcode_39
{
strings:
	$a0 = { 6a0b58995266682d6389e7682f736800682f62696e89e352e809000000[0-10]00575389e1cd80 }

condition:
	$a0
}

        

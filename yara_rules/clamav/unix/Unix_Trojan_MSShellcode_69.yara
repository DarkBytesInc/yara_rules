rule Unix_Trojan_MSShellcode_69
{
strings:
	$a0 = { 6a3b589948bb2f62696e2f736800534889e7682d6300004889e652e809000000[0-10]0056574889e60f05 }

condition:
	$a0
}

        

rule Doc_Trojan_Olerun_1
{
strings:
	$a0 = { 2e7368617065732831292e6f6c65666f726d6174 }
	$a1 = { 2e6163746976617465617320636c617373747970653a3d6f626a }

condition:
	$a0 and $a1
}

        

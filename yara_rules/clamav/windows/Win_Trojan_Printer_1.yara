rule Win_Trojan_Printer_1
{
strings:
	$a0 = { 0100641b69044d41494e6467d7007301000c6a0846696c65536176651273f501641a1b }

condition:
	$a0
}

        

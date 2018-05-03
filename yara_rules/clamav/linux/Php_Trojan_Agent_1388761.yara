rule Php_Trojan_Agent_1388761
{
strings:
	$a0 = { 6d61696c2822736e65616b657231393732407765622e6465 }

condition:
	$a0
}

        

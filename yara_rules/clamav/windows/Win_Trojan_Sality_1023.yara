rule Win_Trojan_Sality_1023
{
strings:
	$a0 = { 60e80000000033c98b2c249081c10038000081ed061040009bdbe368??????008d950010400090424a0314248bfa90 }

condition:
	$a0
}

        

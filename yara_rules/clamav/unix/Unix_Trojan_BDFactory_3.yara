rule Unix_Trojan_BDFactory_3
{
strings:
	$a0 = { 6a39580f054885c0740c48bd[8]ffe5[10-24]0f05 }

condition:
	$a0
}

        

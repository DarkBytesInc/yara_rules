rule Win_Trojan_Bancos_846
{
strings:
	$a0 = { 68747470733a2f2f7777772e677275706f73616e74616e6465722e65732f626f672f736269 }

condition:
	$a0
}

        

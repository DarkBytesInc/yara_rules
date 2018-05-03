rule Email_Trojan_Trojan_639
{
strings:
	$a0 = { 53757065722073616c657320687474703a2f2f[0-20]636f75706f6e[0-40]2e706870 }

condition:
	$a0
}

        

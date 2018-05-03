rule Php_Trojan_Rayman_2
{
strings:
	$a0 = { 3c623e72656d6f7661626c65207368656c6c206279207261796d616e3c2f623e }

condition:
	$a0
}

        

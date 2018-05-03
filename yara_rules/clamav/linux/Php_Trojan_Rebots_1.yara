rule Php_Trojan_Rebots_1
{
strings:
	$a0 = { 3c736372697074[0-5]207372633d[1]687474703a2f2f }
	$a1 = { 2f7265626f74732e706870 }

condition:
	$a0 and $a1
}

        

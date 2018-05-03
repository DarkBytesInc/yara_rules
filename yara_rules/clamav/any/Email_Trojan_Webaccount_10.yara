rule Email_Trojan_Webaccount_10
{
strings:
	$a0 = { 796f75722074656d6f[0-35]70617373776f7264[0-140]206c6f67696e[0-200]687474703a2f2f(31|32|33|34|35|36|37|38|39) }

condition:
	$a0
}

        

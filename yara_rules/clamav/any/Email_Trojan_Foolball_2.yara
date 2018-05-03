rule Email_Trojan_Foolball_2
{
strings:
	$a0 = { 464c20736561736f6e206973206f70656e[0-200]687474703a2f2f(31|32|33|34|35|36|37|38|39) }

condition:
	$a0
}

        

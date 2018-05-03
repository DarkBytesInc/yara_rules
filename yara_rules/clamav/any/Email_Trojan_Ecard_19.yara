rule Email_Trojan_Ecard_19
{
strings:
	$a0 = { 7669657720796f75722063617264[0-50]687474703a2f2f(31|32|33|34|35|36|37|38|39) }

condition:
	$a0
}

        

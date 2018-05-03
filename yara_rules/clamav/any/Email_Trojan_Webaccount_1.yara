rule Email_Trojan_Webaccount_1
{
strings:
	$a0 = { 756d6265723a[0-80](54|74)656d70[0-200]687474703a2f2f(31|32|33|34|35|36|37|38|39) }

condition:
	$a0
}

        

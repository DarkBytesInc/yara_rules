rule Email_Trojan_Webaccount_3
{
strings:
	$a0 = { 4e756d6265723a[0-60]54656d6f[0-10]50617373[0-200]687474703a2f2f(31|32|33|34|35|36|37|38|39) }

condition:
	$a0
}

        

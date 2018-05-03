rule Email_Trojan_Webaccount_4
{
strings:
	$a0 = { 4e756d6265723a[0-22]54656d6f[0-10]204c6f67696e[0-200]687474703a2f2f(31|32|33|34|35|36|37|38|39) }

condition:
	$a0
}

        

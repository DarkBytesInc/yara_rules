rule Email_Trojan_FreeGame_2
{
strings:
	$a0 = { 67616d657320666f722066726565[0-20]687474703a2f2f(31|32|33|34|35|36|37|38|39) }

condition:
	$a0
}

        

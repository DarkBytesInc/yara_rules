rule Win_Trojan_IRCBot_849
{
strings:
	$a0 = { 7363726970745f0076616c75650000006e616d653d22626f745f696422000000687474703a2f2f25732f3f626f745f69643d2564266d6f64653d }

condition:
	$a0
}

        
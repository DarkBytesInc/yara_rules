rule Email_Trojan_Foolball_3
{
strings:
	$a0 = { 466f6f7462616c6c206973[0-150]687474703a2f2f(31|32|33|34|35|36|37|38|39) }

condition:
	$a0
}

        

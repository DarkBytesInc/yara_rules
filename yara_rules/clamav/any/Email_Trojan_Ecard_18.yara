rule Email_Trojan_Ecard_18
{
strings:
	$a0 = { 73656e6420796f752061206772656574[0-140]687474703a2f2f(31|32|33|34|35|36|37|38|39) }

condition:
	$a0
}

        

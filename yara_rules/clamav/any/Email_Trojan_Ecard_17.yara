rule Email_Trojan_Ecard_17
{
strings:
	$a0 = { 5375626a6563743a204920676f7420736f206472756e6b }
	$a1 = { 636c69636b20687474703a2f2f(31|32|33|34|35|36|37|38|39) }

condition:
	$a0 and $a1
}

        

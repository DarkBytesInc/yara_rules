rule Email_Trojan_Softtest_2
{
strings:
	$a0 = { 6f776e6c6f61642074686520736f667477617265[0-80]77616e7420746f207061727469636970617465[0-60]687474703a2f2f(31|32|33|34|35|36|37|38|39) }

condition:
	$a0
}

        
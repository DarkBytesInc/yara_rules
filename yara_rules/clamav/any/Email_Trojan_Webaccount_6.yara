rule Email_Trojan_Webaccount_6
{
strings:
	$a0 = { 4163636f756e74204e756d626572[0-60]54656d70[0-10]50617373[0-200]687474703a2f2f(31|32|33|34|35|36|37|38|39) }

condition:
	$a0
}

        

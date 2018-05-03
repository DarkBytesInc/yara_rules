rule Email_Trojan_Webaccount_5
{
strings:
	$a0 = { 4163636f756e74204e756d626572[0-22]54656d70[0-10]204c6f67696e[0-200]687474703a2f2f(31|32|33|34|35|36|37|38|39) }

condition:
	$a0
}

        

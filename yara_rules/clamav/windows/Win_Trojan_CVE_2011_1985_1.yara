rule Win_Trojan_CVE_2011_1985_1
{
strings:
	$a0 = { 68a201000068ffff0000ff1530??4100 }

condition:
	$a0
}

        

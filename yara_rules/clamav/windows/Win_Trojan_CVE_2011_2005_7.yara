rule Win_Trojan_CVE_2011_2005_7
{
strings:
	$a0 = { 8b45fc506a8?8d8da0fdffff5168bb2001008b55f852ff1518??4000 }

condition:
	$a0
}

        

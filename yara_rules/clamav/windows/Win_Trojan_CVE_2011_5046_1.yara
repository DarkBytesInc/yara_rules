rule Win_Trojan_CVE_2011_5046_1
{
strings:
	$a0 = { 3c696672616d65206865696768743d223138303832353633223e }

condition:
	$a0
}

        

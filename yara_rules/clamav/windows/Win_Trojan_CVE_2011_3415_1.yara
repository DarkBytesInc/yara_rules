rule Win_Trojan_CVE_2011_3415_1
{
strings:
	$a0 = { 2e61737078[0-50]72657475726e75726c3d687474703a2f[0-50]5c5c }

condition:
	$a0
}

        

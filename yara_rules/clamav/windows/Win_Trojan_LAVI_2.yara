rule Win_Trojan_LAVI_2
{
strings:
	$a0 = { 18012d0000b9d60683ea0081e91801268a0289f6342189ff26880280ef004689c083c200e2e983 }

condition:
	$a0
}

        

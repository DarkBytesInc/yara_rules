rule Xls_Trojan_Smack_3
{
strings:
	$a0 = { 4966204170706c69636174696f6e2e576f726b626f6f6b732822584c444154412e584c4d22292e4d6f64756c65732862292e4e616d65203d2022536d61636b22205468656e }

condition:
	$a0
}

        
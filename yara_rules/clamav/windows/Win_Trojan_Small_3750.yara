rule Win_Trojan_Small_3750
{
strings:
	$a0 = { aec3986ea984b1c42598d9be7c2a9ac18ea8acae261581e029c098f1ead897e34ad897842ed0d86e851ef6c97f83efc58ec0a86e262aa16d3bf8a8ae2610988462d0d86eb1b0036f90e3eed826bfaec2360099f3e634cbf963f0a8ae26169846ab800d947cbf70efa2f097cb9bc8ee6dfd40fd }

condition:
	$a0
}

        

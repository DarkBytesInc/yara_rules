rule Win_Proxy_Excelone_1
{
strings:
	$a0 = { a80ec3217e96b192792d23c3cb3a72fa1e046fc1f41b376da2c98a904d233867e0a246389cbf25b5a7984f489513b08fdf3c16716bb9d9f15892f102d4d2f146 }

condition:
	$a0
}

        

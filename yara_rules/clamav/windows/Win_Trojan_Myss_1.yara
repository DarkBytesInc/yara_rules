rule Win_Trojan_Myss_1
{
strings:
	$a0 = { 8d45ecba02000000e8d115fcff8d45fce8a515fcffc3e95f10fcffebe35f5e5b8be55dc30000ffffffff020000003a5c0000ffffffff0a000000526561644d792e6578650000ffffffff0b0000004175746f72756e2e696e6600ffff }

condition:
	$a0
}

        

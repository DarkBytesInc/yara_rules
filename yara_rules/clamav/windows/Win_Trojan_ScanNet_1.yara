rule Win_Trojan_ScanNet_1
{
strings:
	$a0 = { 4244356229f89f22a6543cf0aeb74198c5a032f408908a102878127028c6b5ae48ee2f2c0de3320da2b1db42c1280001229044ea1141db82 }

condition:
	$a0
}

        

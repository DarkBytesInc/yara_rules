rule Win_Trojan__1793_0004_000_1
{
strings:
	$a0 = { 9f0283069b022c90b9910233d2b440cd21e823feb90002f7f183fa00740140a39502891693 }

condition:
	$a0
}

        

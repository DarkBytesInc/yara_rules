rule Win_Downloader_271_1
{
strings:
	$a0 = { 24584266d1ea2c8941d8aa961dc559b2d99f05c3ebf8f14be2eb99a11f75adddc07cfd8b19c1a46cbf5451109a50b60adec7667b41533927a1793d8f951351e30781ab7a2e64b2a64828a22de7d2 }

condition:
	$a0
}

        

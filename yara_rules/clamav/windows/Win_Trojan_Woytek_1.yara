rule Win_Trojan_Woytek_1
{
strings:
	$a0 = { 0400d1eaf6d6d1ea86d6d1eaf9d1eab97806d1e9d1eaf6d6d1ea86d6d1ea2bf633f5d1eaf6d6d1eaf9d1eaf9d1ea2bd281f2471fd1eaf6d6d1eaf9d1ea0bd27502fec6d1eaf7d2d1eaf6dad1eaf6da2e3114d1eaf6d6d1eaf9d1eaf6dad1ea4646e2d1 }

condition:
	$a0
}

        

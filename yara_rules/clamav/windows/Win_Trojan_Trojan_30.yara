rule Win_Trojan_Trojan_30
{
strings:
	$a0 = { df22354f7f4cf1d31644b16967f5b9c7c5458e7547cfaaa6273705cdf96b696463616dd8c6cb9b6a277295d5b39a0fed3e9d7069cf3b5f7127e3bcf3db8d47229b5bef9e71f4ed77742da3a6a2b68cc519273e8ea61bf6d55ed8 }

condition:
	$a0
}

        

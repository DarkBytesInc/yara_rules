rule Win_Trojan_Small_5310
{
strings:
	$a0 = { ed3e81eb85ab553389566d2e4a6fc3aa5d97bd01f057c0136e6aadabda3edfae8556f06f9e55e2cf9d5583b395966d0ae4b3c80449adc41386666dabef5e6cc0bd66adabd55583e795966d3676c16d15a9acd7ab846cc1bbc556f26bfa88f8e8b566adabdb55453046cb9201852eee27b655ca }

condition:
	$a0
}

        

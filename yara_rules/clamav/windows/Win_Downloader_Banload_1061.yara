rule Win_Downloader_Banload_1061
{
strings:
	$a0 = { 8ccf287ffc76bbf294a2cc5ac4fb1874d2eb16d1756274bc7a6eec5d9f98e244ccf9de571b454b4eb87612973b6000b072dd5abf35b2fb1c9a40641f5a45ecfcd4563fa9cfff8545122e54bba621016725e6adb41f28170d71253d901ab231bc825ee2c246bfbb2cdec7ee280eec5a2203307e47a6c035cf }

condition:
	$a0
}

        

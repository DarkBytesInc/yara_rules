rule Win_Trojan_Mybot_5459
{
strings:
	$a0 = { d11cef3ebe35f4c6bcb376bdb0c194b79a2870902221d86d7df27b2852cc1fbd8da07c5466e095b54d4d14d876ae9861bfff1449fbafc3ff822ff2fa43bbc56aed7ceb025564dd1d264f86a8a9afa59fd69ff283b4eff92a071a1bba29ec8488f8bb9eaa5825162934 }

condition:
	$a0
}

        

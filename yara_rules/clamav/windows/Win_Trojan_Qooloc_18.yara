rule Win_Trojan_Qooloc_18
{
strings:
	$a0 = { e6943d35b99a25aa214488cb98dfa3e1bd9021954f12369f54041a4dde70d106b49c0e25329b6d2d4cc7ac9a3ac2506d431024a062c623ada06d217819d2798de1d39766da1aef0123ee5f6d214edb84c76e66a0b443ccd7d9a2cb39dfcf3a27c9cd37c5db9be254b5786c93c5c99ff2e9e4edb321b60adc793fb0 }

condition:
	$a0
}

        
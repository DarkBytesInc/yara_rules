rule Win_Trojan_Boxed_7
{
strings:
	$a0 = { 100e7deea7fb284ddf7c63d600345afaa530fafb191c713ed7b0c803135c6e714c0401756d6966a9f0ea07041c0e2da691bd3e7c43ff79203b954fb63033b8173472bfbb461e48d43d50d0ce0142a5c2450aa45bd50e77358c6dd055df0f8096e6a3b0d575d41a269060216652b3e3de1563c7dfb29993334ffa098b12d4459c48e1f37c80c0f67585faeb0649ad19e9ff3ccdd3f310 }

condition:
	$a0
}

        
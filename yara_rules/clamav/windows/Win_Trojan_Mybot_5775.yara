rule Win_Trojan_Mybot_5775
{
strings:
	$a0 = { 5a7d45aa4cd7339af1555ba8f46b02d2fc0fbc70eeab432a085a6d591b52de3873a47f16408b3973d5de59a11b50841e86c3f4dc379f71f4b28a7d4258a4a3cfc1973af76a233820e2eb86cd96df606644c4aa172ddba82248fac1535e1fac0aef6052761789af8d19e17a2769ebb3bc98bb305553e690b0500acce9842777b02e4b50b932c2f3d1d745a99f }

condition:
	$a0
}

        
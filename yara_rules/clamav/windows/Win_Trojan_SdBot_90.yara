rule Win_Trojan_SdBot_90
{
strings:
	$a0 = { 33325c25730025735c41444d494e245c73797374656d33325c257300000053594e20666c6f6f64206572726f723a2025640a000000004261642055524c2c206f7220444e53204572726f722e0000557064617465206661696c65643a204572726f7220657865637574696e672066696c652e00000000 }

condition:
	$a0
}

        
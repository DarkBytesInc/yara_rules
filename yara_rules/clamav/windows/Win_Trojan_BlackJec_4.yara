rule Win_Trojan_BlackJec_4
{
strings:
	$a0 = { 4469676974616c20462f58205669727573202d2043726561746564206f6e20322f352f39322062792050686f6e65792050687265616b249090b98000be8000bf }

condition:
	$a0
}

        
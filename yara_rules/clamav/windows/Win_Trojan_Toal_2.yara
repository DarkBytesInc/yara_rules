rule Win_Trojan_Toal_2
{
strings:
	$a0 = { 8d7d04f38bd9569f6ffd355d52edab92315040b48bcbe2d80b11b6e62114108355105718ff3f57f103f8b94b0b295c494e564943545553e0f13f12c35efcacaae2fc8d45149806edd05759036853fb228dc359e3898525346a6fdcad96f88559840832c0f2ae2749b62245da62 }

condition:
	$a0
}

        
rule Win_Trojan_Mybot_6258
{
strings:
	$a0 = { e8af1c00005eba44a14242dddf6325ded304c26a2abeddae6208f3b3604352d07f0ad946a82c343261fb6476e5dbf71d5aa12e57d2c6aa6d24adf3a018acf85f50ad340bf5863b7fcf1f3a6069a2835c1ca742b195197a23d06d32994808254e77f4954b }

condition:
	$a0
}

        
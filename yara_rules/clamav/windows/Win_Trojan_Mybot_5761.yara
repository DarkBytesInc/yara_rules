rule Win_Trojan_Mybot_5761
{
strings:
	$a0 = { abd76daeb1e75ce2443e0923570f2f1dee3d023a58919bd9ecd9276fe516d2c1407777f2baf5fa1c32779ca0fca39abc3f4e6bdc4a6270d136d2038020eb07f6ffd8af785ed6b389047765acac41ea3168dbf18d0dcb14331df7cecbd4bd47ec8fca3a11ef5f633022d52f74b51e3c3c0c3c26762f88 }

condition:
	$a0
}

        

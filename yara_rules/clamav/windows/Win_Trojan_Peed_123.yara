rule Win_Trojan_Peed_123
{
strings:
	$a0 = { 686e93faffeb6389daf7da01d0ba5700000083f8000f84ad000000c3f7db29dff7db01de89c3eb0fbf00??a8e1bbf9ffffff01c789f89683c30783c40283c402b847130000e8bdffffffeb35ba010000004a87ca83c40583ec016a02ff1558??400069c0 }

condition:
	$a0
}

        

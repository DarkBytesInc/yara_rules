rule Win_Trojan_Mybot_5200
{
strings:
	$a0 = { d8a759f13d0cf6c845d31c19cec40ddc2c0ae32b512a5e3e4f03a9ac884a0b6e204e4161775ca8d3dab5cedf657bdf1d75adcaf5630ca184e6a4a4ede6261d48263919ab7ee8cf87d00bc38396bcbcda62e1141e0237a7359388815009427c69e09b448a7fdbef717f06749c11c7936a01ca3f9f7bd101bb0f5d5c1d4ee23dd443f36c9e0a25a3613460d600b5e6 }

condition:
	$a0
}

        
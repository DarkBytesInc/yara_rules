rule Win_Trojan_SdBot_2686
{
strings:
	$a0 = { 3019f7a38e611aabd16f15a1b551c223136206f52969c5a197bee53041552f382a4985f5d4e04163564a5207e6f292d95ccadbfb0e9d2d5223fc0c36940d59966d38977dbbf0fc249cd5f534ac2a8bfb7834cf0fe34cae0e78533c81475c256f2972626985e3435cc84f41002ceb4aa76f7f4c5b3fff76ea23edb45e1fc70910085391e91fe716c3b7cd14b11b40e78f19ec665aaa3c }

condition:
	$a0
}

        
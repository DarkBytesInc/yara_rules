rule Win_Spyware_Banker_3508
{
strings:
	$a0 = { 342dfc7d8e33994e956e2671db7e51dabe31e892602e381f6148b97a6e444ca9be33d5e43ca60c6b74f180656eae3132beddeb7e2f942c94d15ced81acc36ddd1a2838412f3a3622e5a0eb75899736fe2dc232aaa2b6c5746d6e }

condition:
	$a0
}

        

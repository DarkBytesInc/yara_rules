rule Win_Trojan_Mybot_8466
{
strings:
	$a0 = { ec40c964281ad12cd0ac0356a268ce814e915211ce559adc24ec5491b6b329f09a9afbbbb35b475891c453f4f191b1a2999e0fb9cef5c0f0dbddcef98dd9d18147531ecab496236450093c2a35cf95d35e1b5f27ca }

condition:
	$a0
}

        

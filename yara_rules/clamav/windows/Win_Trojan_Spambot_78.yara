rule Win_Trojan_Spambot_78
{
strings:
	$a0 = { 1c15b74366ff7ff5ff03d21dd6c6e340ee8be18a87a3093ee0fed6329bd8a2108eaf9aff8f4dfcf40d8202e0a42b31ec72085be7701bad07ffffffff3c3a8717b5c88d4a1973fb68c9927d700aac6e8f02b38cee9b6219815d4d2643ffffffff104dafce715374c72c00f2638a14 }

condition:
	$a0
}

        

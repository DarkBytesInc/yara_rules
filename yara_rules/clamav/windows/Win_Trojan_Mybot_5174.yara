rule Win_Trojan_Mybot_5174
{
strings:
	$a0 = { da5a671a7f0149546b37d3d81195c3c347317f2beecb6d229f40ba7f3980e826cef46675f1cbf58fc15e8b8b57f93e37695d32914454b81d4c93248b069e8e786851f846c457a0777c23c91628cd72e4a74d7ac2c180442b439d6c9d8d1da31605ebaf771130ed60dad556ede8ab101d3fd605362794df389b39ce3001d6d31235d99a62c75fc8f88e2ca05672d730362b682a568cb3 }

condition:
	$a0
}

        
rule Win_Trojan_Agent_32901
{
strings:
	$a0 = { b07e1eb1e26dea3a7f66d6c1bbbf5bb69aa6b97ef29a54f0b7800147e6949c86d37d1e141d4adae3259da4cebd9d76a523c5d4cc1f7b3db0e2f419cd5b61da80148ad83c145e96721dcfb6d8c84b5d305c013c4c25 }

condition:
	$a0
}

        

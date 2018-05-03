rule Win_Worm_Stration_497
{
strings:
	$a0 = { aab7aacf235c2e65786533fffffbff280f070e130c0015080e0f610f86a3b7b2a7b6f3a0a6b0b0b6a0a0fbffedffb5a6bfbfaaf3babda0a7b208b6b7fdd3000e1e51564d1e0e232bffeffeffe9e7f0ece7eeb1b0ace6eeee820f596f677a48617c5d67606962 }

condition:
	$a0
}

        

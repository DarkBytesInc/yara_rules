rule Win_Spyware_8943_1
{
strings:
	$a0 = { 100100002aa2d988378c64f9f18abed3fd33e6791c2c93021e9c90eff60bb50ec5bf6d5b0eea4d256375fccd73ad77b2a4ba60669eee0b803fea00fb7b3dfba1ff6b4784a6c2ce6ad053e797b946ee913bf6c3baa8f46cbb25adb6ee70c023824b8c8f3048d2b79d65d2fc1050bb816992c5ef }

condition:
	$a0
}

        

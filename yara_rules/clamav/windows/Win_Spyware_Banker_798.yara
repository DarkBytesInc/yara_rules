rule Win_Spyware_Banker_798
{
strings:
	$a0 = { d4057bef9175f3a3f2f51e7726e58361279a6a8fdeee82c1803b0bc289d9b25205abf0f0f534a5fd3c0721046c4c58f21f268809120606ae3d1685c8566f14277c6e31f6a9718ed27c3b43045430f1d64f23eca681b9e53cf199f26463e2fc6e94d416f8cb3f1f333b1d4164f9881ae03ded978e43146d03247e9a5e44faa442e0d883e64bbd1de48e24751e0061e9854cae81404ce2 }

condition:
	$a0
}

        
rule Win_Spyware_Banker_2763
{
strings:
	$a0 = { d9192b7bd109e90150fc4f8788147f199b999adfbc105edf38ce5515f6d1171fb2a1c2f51a3dfb134e2fa9a32305fae70ff62edcd456a5005677a747d1bc0f63fab67f60aa4beb3d0767bc37150dc19c6f9db787408de8fb93b4dea7de3d070bf436d7c3b57c1cd0ea6a7bb6a866b4810767c2a102846d4ff5a80150 }

condition:
	$a0
}

        
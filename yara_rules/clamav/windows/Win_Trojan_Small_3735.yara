rule Win_Trojan_Small_3735
{
strings:
	$a0 = { 52d6bafa69d17b13c04d8f3bbaa421fcbcb69f0eaa4e0ce3db51b7faec12d0f9de72cff97f56c73a6aad1558c5a77a51c1b6b70a6a4e21036963ef0aaa4e07fa7f8ac73a6ad9a7656ab8da50d44eb610be5ef7faee0e2c2df58be70aaa4e0dfa41d3776f8fa4b6d2eacae7f9c6c3bf50692538 }

condition:
	$a0
}

        

rule Win_Trojan_Mybot_6637
{
strings:
	$a0 = { beec4fb5a574fb2586a164d9bf1e41d3b866e47ca532b5bcc0bba46328c03ae1cf9e86ce2d3667a4bafc99c0d911796375f24c523849598fb1605c9d5f910d967ab6d1dbf84f54f60c1851b0f8532e4b3a547602c59234b6f35072d30736e16f02e0899a81113fda579be753f2b24c74cdf652450b0d6b6e7da1ef08d4baf2e103c2850ce59534e2de81bbe5eae0915686fad875934d }

condition:
	$a0
}

        
rule Win_Trojan_Hupigon_925
{
strings:
	$a0 = { b4ab2f92178d5eedf2e84dafee9267a627eae0a58ce886909f6fbe8118b488051113a4d2294b9b43aa1a408b559ece6fa6d4f27dac01c338eed230b9e3dbeffa566521b58dd29d87bc1b83f9d33a2c278f5187146f6cc67c7b609d2042ba6566488b }

condition:
	$a0
}

        

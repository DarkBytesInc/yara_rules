rule Win_Trojan_Mybot_8441
{
strings:
	$a0 = { 20fcf50164fd2eacb611a9bed0fc1d9d19201954d597d2c7326261c447d57539507bba580706de39232ffdeebfb32161b9e27a74e66efa8a9c974fcd779e9c87ca3951135aa8d4086fe6df0accfb3b3c6f18397e69 }

condition:
	$a0
}

        

rule Win_Spyware_Banker_353
{
strings:
	$a0 = { b66c9f7829e455d881356f71951d4969ef82797f8d129f71cb26db053a0bbb558a72419f98cb50a7db0c5a78aeb515c2ee917364d235395987fc3d3cee1955c5b773d6f4b0f5436e73f8e8ec26c24937e1bc67636716a9940519744389431273344f5404acbedfeaaffd40737cd80f0767713bd93a13544f8c671c0b4f6172f54f6d0784cf7a1fa942e84e8e7bdc9bbc8448a76aae8f }

condition:
	$a0
}

        
rule Win_Spyware_Banker_2042
{
strings:
	$a0 = { 42eddb7deaccb702a9fbf863813c0efe84badc14b23e75e0ef71b9056752647a641f87e6818e49de9374fc5bb0a397461245969ee1f8d11b4f6cc9c4cab3ea645a764150df842b053a08d02faaad0809b89ba72226b35e0a1ce40d9c548c8c19532a622bd34c3003ab8557511a2de4e71408933e39a208fa6e4a214a9cf035ee50c6e2caaa88cd6ff9bc2e6fac9aeddf20 }

condition:
	$a0
}

        
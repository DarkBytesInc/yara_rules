rule Win_Trojan_Spambot_139
{
strings:
	$a0 = { f3bd3a6e3be5ce453aaa52de592cc8f5e887982777df798f0219fffaffff5140d7beeec8e0875e4b6c851257dfbafaec6bb52941b12937a8ffffffff346667c95f90a297bbf744a4fdc7a4a4c7552262363e6efa891f7a91afe50adfff47ff472f6813bd19323d8e2e6ad79ee686 }

condition:
	$a0
}

        

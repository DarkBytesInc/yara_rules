rule Win_Spyware_Banker_2092
{
strings:
	$a0 = { 9b81def4f0a6a33703bc05d19b19deccf41657dc8f2d2fe3fa6df019444aaddcef30e639b92d1575e2527c10bae2be2cd1f7a9bfda800726e2afa47542da8e34b393aad391d6975ef41d69fde825a8234d472f868eb4207a3177a4e9e9254ecb48b5c3ee2fe7f3755ba09ccf1fce29723eb64ee914fbcfa2 }

condition:
	$a0
}

        

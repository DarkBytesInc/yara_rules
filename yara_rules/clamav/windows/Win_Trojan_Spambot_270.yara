rule Win_Trojan_Spambot_270
{
strings:
	$a0 = { 13b9672b31e2b131db0f2273b85cb7ffffff8f7021381fbe2fea8821daa3f6a651ffc2b1817b4b97a0575ba554ffffffff17c6cdeca0f16908867e8e761083e3595e21541022fbb66fcf92801603efb0aaffffffff776e6cd26034e177c44d2ff181895eddec34606cc711ffe854 }

condition:
	$a0
}

        

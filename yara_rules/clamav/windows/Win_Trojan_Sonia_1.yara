rule Win_Trojan_Sonia_1
{
strings:
	$a0 = { 4000e84d000000685d20400053e84e0000000bc0759f8b3da923400047b822000000b904010000f2aec647fe5f6a01ff35 }

condition:
	$a0
}

        

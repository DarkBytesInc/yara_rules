rule Win_Trojan_SdBot_2353
{
strings:
	$a0 = { 54d7efa053e69c9ebc9eee8ec21b7dad98c0a317ac5cdae15079d26fdef9415e278852d46bdb0e6dae31ffd4cceadf348c0afd4e3fcd82b4e63ba49d0208cbf8cb0d61d7b4aaf792b7869d4da9a520af6196301dfd6e00ea394a35d1d7704dd6f765661a8f1af6c6d9673083af6cc88569a1a1f838e690ac4884 }

condition:
	$a0
}

        

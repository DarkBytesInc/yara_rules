rule Win_Trojan_Hupigon_839
{
strings:
	$a0 = { 44fa05e5ec9147c53bfc9396ddff8ac018339a3ccfd53118dea0a9de05fa9b4928e81e02c1dd37a1f91442c6352120b2ccbb0bfcc6f78fff73633880ee65f94aa7aeeeaae35b2664918463ce07cd824d1b6268f908ab0ca6e8941ba5a7c0d1 }

condition:
	$a0
}

        

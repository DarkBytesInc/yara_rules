rule Win_Trojan_CholeraWorm_1
{
strings:
	$a0 = { b7cfb3baadbedfd2dfbd9e9c8b9a8d968a92dfbd9690bc909b9a9bdf9d86dfb88d96a690dfd0dfcdc6be00bc9e9191908bdf908f9a91df9996939ac5df968bdf9b909a8cdf91908bdf9e8f8f9a9e8ddf8b90df9d9adf9edf899e93969bdf9e8d9c9796899ad1f5f5b699df86908adf }

condition:
	$a0
}

        

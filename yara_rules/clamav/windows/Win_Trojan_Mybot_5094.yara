rule Win_Trojan_Mybot_5094
{
strings:
	$a0 = { 57d92aa81462213da1a81571af202ba64b9e9059a1755f3d507e04b7f803abe3355e4a86a32029d24c41689d758ba63c0524a3181c6ed0b32f53daf376eb840dc7051054016414142c04891015f6cf9261300ca141276bc0da904603c8bd0a1fd3cb57b30d9ff273254404b0bd2c2b515a94fcb3739138137332e70df45e441422d37e34 }

condition:
	$a0
}

        
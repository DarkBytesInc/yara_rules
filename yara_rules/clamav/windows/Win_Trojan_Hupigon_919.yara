rule Win_Trojan_Hupigon_919
{
strings:
	$a0 = { cd338021461afc16709c83b1d1299f69b6fad80083e13ddb7d6c4beddedb68d08ce885971e18c2f0c98f0c418686a6bda6daf473c30d8b5db5ee10bef0c2afc2609141b520506d4d9a36164b4dee41f4d29088706a3a0e6afcce960044fe6e08cb68 }

condition:
	$a0
}

        

rule Win_Trojan_Agent_32736
{
strings:
	$a0 = { edffff8bd88b45fcf76df833d28945e88955ec8b45f433d252508b45e88b55ece8d8e2ffff8b4d0c89018951048b45f033d252508b45e88b55ece8bee2ffff8b4d1089018951048bc35b8be55dc210009089fa89c7b9ffffffff32c0f2aeb8feffffff29c889d7c390568bf092e8 }

condition:
	$a0
}

        

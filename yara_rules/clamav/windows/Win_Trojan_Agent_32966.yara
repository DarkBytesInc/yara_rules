rule Win_Trojan_Agent_32966
{
strings:
	$a0 = { bad1808a79290fa4f861502ea4e09b68f9fa91b7f4ab98fb9da41c7d1922b3781ebf1b2a0ca46e4f3abf4f48e10d07e1f8c6834b0be0c083058a8c942e19369b45727aa948b4b95909715640a9d0 }

condition:
	$a0
}

        

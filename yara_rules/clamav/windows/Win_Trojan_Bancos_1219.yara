rule Win_Trojan_Bancos_1219
{
strings:
	$a0 = { 2e6c2bc2ce7a793a6ee9ae14d0121aeaa57cf5ce3953b2bc7a0bbeb2c7119c6d50c090313c72b3c8dce72ecbebf76a73b4934f3844eab6b0aab08afaf82f6fee70baddd0e260f59b5c8768589946d4ef8a51859925e05e3892108c8188f0a7 }

condition:
	$a0
}

        

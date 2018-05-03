rule Html_Trojan_MadtolA_3
{
strings:
	$a0 = { 62d9fc3febb6970a65d36d275dbcf8689c10f2a41cad93f441016ae058947f85e4e6718f7a94d0ba0645420a6137a707d1610a372e95ed01c05102691ba50b6e }

condition:
	$a0
}

        

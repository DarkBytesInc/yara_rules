rule Win_Trojan_MicroBot_1
{
strings:
	$a0 = { ed3684cdc6a773366e6756d9ecdffe556e6c696768742b5878537079785849a7bfb5ff04486f6d6570616765544f74703a2f2f20b40db777002e65 }

condition:
	$a0
}

        

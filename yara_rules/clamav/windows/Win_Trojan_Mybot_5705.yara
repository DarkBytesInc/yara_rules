rule Win_Trojan_Mybot_5705
{
strings:
	$a0 = { a06e92a4e128f1d07006f263603f62f138022ca868cfe932cb99cf5d1c4ae146ff71faaec67d12433a8693ad9c4e2f537407b6d1fec8e1a87be08e8f769a0d46106ef7686b3bce0baf59cf6993a7081e58b9ce23724d9bdd016a }

condition:
	$a0
}

        

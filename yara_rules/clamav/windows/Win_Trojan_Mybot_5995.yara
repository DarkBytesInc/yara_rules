rule Win_Trojan_Mybot_5995
{
strings:
	$a0 = { f6382b2da2549268ec5352cba89be1dcee26f96a7ef3b765c6e676e07afec1e8e80584011c47cee62f489351e505e6eb777a84ce4cabf254194a6836552db622de04658a3aaa8505202b79bab0b16772a7cd }

condition:
	$a0
}

        

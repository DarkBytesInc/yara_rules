rule Win_Trojan_Mybot_5538
{
strings:
	$a0 = { 5734e7b0eb79bb704321d51ca92e05af824012ca4b19163f7b5724379fe883188e22b34dc53f22d6525359fca88354ca5cced41c7d352a2bdeda56e78b2384948fa27a606be6 }

condition:
	$a0
}

        

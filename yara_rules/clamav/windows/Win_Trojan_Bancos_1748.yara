rule Win_Trojan_Bancos_1748
{
strings:
	$a0 = { 3092826b8e6092a91eafa320538432291fdf78469f84706fcaad6e8aff228b83850ef56d4bb4b073af794b0f3d97dae3482fa04b04376af0d819f6255f58bd36a0588b1c14d1 }

condition:
	$a0
}

        

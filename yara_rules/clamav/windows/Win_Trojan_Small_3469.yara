rule Win_Trojan_Small_3469
{
strings:
	$a0 = { 02c557b34775a55a6cbc64714dfa13d07a20b166e049dc462ff8597c641abf4ee84f01290ee15826307670bdd70be6181ed62d03226f422358e5df3ed7da6f083526e9d01cfbab4cd28ded5239ef }

condition:
	$a0
}

        

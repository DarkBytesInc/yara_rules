rule Doc_Trojan_Armagid_1
{
strings:
	$a0 = { 5543617365284e4929203d20222741524d414749444f4e22205468656e204e54696e66 }

condition:
	$a0
}

        

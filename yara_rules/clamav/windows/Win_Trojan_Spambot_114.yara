rule Win_Trojan_Spambot_114
{
strings:
	$a0 = { ae5a809ce38626deffffffff4f5e5ad708d1faa217043586580a59ad05fb8be694daa73dec640c80b9f9e518ffff7ffcae0669d54a89912fbe7ec43bcff43a8e00662aeb5df9e400a270ffffffffb506ef270b84f067ad5efd4704c1267a0af1f072d47800cace514e4bd31364c0 }

condition:
	$a0
}

        

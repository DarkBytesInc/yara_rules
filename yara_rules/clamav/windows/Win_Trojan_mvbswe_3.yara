rule Win_Trojan_mvbswe_3
{
strings:
	$a0 = { 6f70656e20222026206368722833342920262022633a5c6d76627377652e766273 }

condition:
	$a0
}

        

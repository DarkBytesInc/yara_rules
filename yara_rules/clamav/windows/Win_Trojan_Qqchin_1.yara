rule Win_Trojan_Qqchin_1
{
strings:
	$a0 = { 369ce8f6ffffff9debf1c2ccfdfdffff9090606a40eb3c8db525feffff8b0683f8010f844b020000c706010000008bd58b85b9fdffff2bd08995b9fdffff0195e9fdffff8db52dfeffff01168b368bfdebc090680010000068001000006a00ff9561feff }

condition:
	$a0
}

        

rule Win_Trojan_SdBot_2633
{
strings:
	$a0 = { 369ce8f6ffffff9debf1c2cc31feffff9090606a40eb3c8db559feffff8b0683f8010f844b020000c706010000008bd58b85edfdffff2bd08995edfdffff01951dfeffff8db561feffff01168b368bfdebc090680010000068001000006a00ff9595feff }

condition:
	$a0
}

        

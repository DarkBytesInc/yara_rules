rule Win_Trojan_Banker_6354
{
strings:
	$a0 = { 89b5b1163b088985551e3b0883bd11163b0800740c8be88be2b801000000c20c008b44242489858d }

condition:
	$a0
}

        

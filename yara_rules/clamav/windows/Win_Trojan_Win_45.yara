rule Win_Trojan_Win_45
{
strings:
	$a0 = { b801d600008db7c9284000cd2032004000b800d70000cd203200400061c687c4284000008b451c50 }

condition:
	$a0
}

        

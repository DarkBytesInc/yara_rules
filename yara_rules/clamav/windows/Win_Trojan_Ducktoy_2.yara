rule Win_Trojan_Ducktoy_2
{
strings:
	$a0 = { 4475636b746f7920312e302e31202d456469746f722064656c2053657276657200000000ffffffff }

condition:
	$a0
}

        

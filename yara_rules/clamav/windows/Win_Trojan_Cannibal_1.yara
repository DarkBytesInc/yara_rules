rule Win_Trojan_Cannibal_1
{
strings:
	$a0 = { 0b01eb00ea1c001700fa2e8c1600002e892602002020206279746520434f4d20746573742c20313939340a0d }

condition:
	$a0
}

        

rule Win_Trojan_NTRootKit_1
{
strings:
	$a0 = { 642e0a00726f6f746b69743a20666f756e642068616e646c650a00558bec51c745fca0a901008b45085068c0110100e8 }

condition:
	$a0
}

        

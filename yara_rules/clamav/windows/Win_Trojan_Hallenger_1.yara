rule Win_Trojan_Hallenger_1
{
strings:
	$a0 = { 4554293b0d0a09636c6f7365736f636b6574287368616e646c65293b0d0a0d0a092f2f424547494e2041545441434b0d0a097768696c65283129207b0d0a0909666f722869203d20303b20 }

condition:
	$a0
}

        
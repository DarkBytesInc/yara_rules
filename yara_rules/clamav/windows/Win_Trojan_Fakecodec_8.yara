rule Win_Trojan_Fakecodec_8
{
strings:
	$a0 = { 038d5cfdffffff8d70ffffff198df0feffffff1514e04000ff1514e04000ff1514e040008985bcfdffffff1514e040008b8d1cfdffffff8da0fdffff218d14ffffff218d54feffff298d28ffffffff857cffffff01d109ca81eaa200000041ba8f000000 }

condition:
	$a0
}

        

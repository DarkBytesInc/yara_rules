rule Win_Trojan_Philis_22
{
strings:
	$a0 = { 202020202020202020747900ffffffff05000000646f776e3a000000ffffffff07000000e8f4f4f0baafaf00ffffffff0300000064313a00ffffffff010000002c0000007e }

condition:
	$a0
}

        

rule Win_Dropper_Agent_33934
{
strings:
	$a0 = { 6a006a066a026a006a0068000000c068b8424000e8f9faffff8bf057a15066400050e82bfbffff6a00686866400050a16c6640005056e827fbffff }

condition:
	$a0
}

        

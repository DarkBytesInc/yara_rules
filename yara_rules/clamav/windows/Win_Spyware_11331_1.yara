rule Win_Spyware_11331_1
{
strings:
	$a0 = { 6a008d55dc33c0e8c0c2ffff8b45dc8d55e0e841e8ffff8d45e0bac4650051e874d5ffff8b45e0e864d7ffff50e8deddffff8d55d8b8dc650051e895e8ffff8b55d8b8e0860051e814d4ffffb8e4860051e8b6d3ffff6a00684c0400006a646a00e8faddff }

condition:
	$a0
}

        

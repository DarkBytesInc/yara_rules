rule Win_Trojan_Hupigon_148
{
strings:
	$a0 = { 6a00a1a8e248008b00e80c96f7ff50e812b9f7ffa114e24800803800742ca1a8e248008b00e8f095f7ff506a01a1c4e048008b00e8e195f7ff8bc8bae0b84800b801000080e818bcfcff }

condition:
	$a0
}

        

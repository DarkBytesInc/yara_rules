rule Win_Trojan_Agent_32807
{
strings:
	$a0 = { 02b7d0ad87657cea1224b6ec42a309f0f0417338d32449b7d46eebabd80d947d3d33748b806f9629a4040c389df1f021bbe324c58cee1dc77f6557277e899977b0 }

condition:
	$a0
}

        

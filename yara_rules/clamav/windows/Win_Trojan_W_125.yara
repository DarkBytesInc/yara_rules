rule Win_Trojan_W_125
{
strings:
	$a0 = { 4a686f70610d606845b40000cd200d004000590bc07435c6857c040000008bf8578bf581e9c8af0000fcf3a45f8d }

condition:
	$a0
}

        

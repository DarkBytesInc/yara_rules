rule Win_Tool_Shellcode_13527_1
{
strings:
	$a0 = { 31c031d2b230648b0285c078c08b400c8b701cad8b4008eb078b40348d407c8d403c }

condition:
	$a0
}

        

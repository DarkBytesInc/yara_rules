rule Win_Trojan_Hupigon_51
{
strings:
	$a0 = { 6a00a1b0e248008b00e8b091f7ff50e8b6b4f7ffa11ce24800803800742ca1b0e248008b00e89491f7ff506a01a1cce048008b00e88591f7ff8bc8ba48bd4800b801000080 }

condition:
	$a0
}

        

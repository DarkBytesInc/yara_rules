rule Win_Trojan_RemovWGA_1
{
strings:
	$a0 = { 2446696c655f4c6f67203d204054656d70446972202620225c5747415f4861636b65722e6c6f6722 }

condition:
	$a0
}

        

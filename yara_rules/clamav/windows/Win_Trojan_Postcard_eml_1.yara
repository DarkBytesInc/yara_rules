rule Win_Trojan_Postcard_eml_1
{
strings:
	$a0 = { 706f7374636172642e6a70672e657865223e687474703a2f2f7777772e616c6c2d796f7572732e6e65742f }

condition:
	$a0
}

        

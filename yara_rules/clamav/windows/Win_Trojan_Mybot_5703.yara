rule Win_Trojan_Mybot_5703
{
strings:
	$a0 = { 9c16ff5cc21f51817d9cb2ffefddd7273e1d4d98ffe6982053984d9c7efe86197819a4f9a48520ff0d151cfc0e6e3b59ff0f8d91eab6f5b0eda55e58ff6096eb64886c8315ff2092b7ca2fdbee8e8d6428ad10a1ffc0246e988a }

condition:
	$a0
}

        

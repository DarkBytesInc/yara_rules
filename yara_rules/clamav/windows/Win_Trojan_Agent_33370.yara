rule Win_Trojan_Agent_33370
{
strings:
	$a0 = { ae141f6729b8929aa4aaefcde7942247f15ba420229380dccf7381b33dede9373d881add1b54f8f34ccb0eb816e57de7fc6549c72c3044a826ef555cdb5c7dbed853afc04bfa6b8f9b00b79bc9ff22939d5fda7896696f751d473c42 }

condition:
	$a0
}

        

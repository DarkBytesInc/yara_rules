rule Win_Trojan_Dialer_903
{
strings:
	$a0 = { ee6c6561413d6f3d6826262a3d7953666673fefdfedf6d6103646173322655524c7041763d77012e6d656761c5b6bbe08f1c6e6964 }

condition:
	$a0
}

        

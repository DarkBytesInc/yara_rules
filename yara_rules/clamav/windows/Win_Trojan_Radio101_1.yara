rule Win_Trojan_Radio101_1
{
strings:
	$a0 = { 2e803501474875f8e901015f82ef1032c15151b5f8cc2081fd08755a2fc685e9020101571f078dc1498fd9bac901281f }

condition:
	$a0
}

        

rule Win_Trojan_Agent_35190
{
strings:
	$a0 = { d1da4b4a9a434e0866e1e6fe8097783625e1d880e7930ded2ea291d224eb0b619ab7ef11de9162bb00164e271147202c44eab946e2db97e614019585b09ee4dadf7235dc8dce249dfd7f0b5b0135 }

condition:
	$a0
}

        

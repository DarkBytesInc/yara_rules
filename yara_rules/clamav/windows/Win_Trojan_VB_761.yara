rule Win_Trojan_VB_761
{
strings:
	$a0 = { 474f4c4420652043415348204861636b204279205762536b756c6c }
	$a1 = { 4f63756c746172204c6f67696e }

condition:
	$a0 and $a1
}

        

rule Win_Trojan_DL_1
{
strings:
	$a0 = { 460183d200b90002f7f183fa0074014089968b0289868d02b440b946018d960001cd21b8004299 }

condition:
	$a0
}

        

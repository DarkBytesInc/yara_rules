rule Win_Trojan_DL_2
{
strings:
	$a0 = { 48019083d200b90002f7f183fa0074014089968d0289868f02b440b94801908d960001cd21b800 }

condition:
	$a0
}

        

rule Win_Trojan_Weird_5
{
strings:
	$a0 = { 5060e8000000005d81c5360200002e8b4501909090894424202e8a5d009090908d453990909084db740a909090908d85ac000000 }

condition:
	$a0
}

        
rule Win_Spyware_Banker_2803
{
strings:
	$a0 = { 089912ec935fa219c732fe6d87518a7fcccb176c0d6fe95e6a294537b9b12e8edfdc5b409d63071c07f1c2675dfb7f8df0d3d013a17e9812237e6d8761139dc98b01d0dd6a02ffd5b4ec082bbf4f546f8d2fd283a17ed0faa3001724f8f2140b2a114511 }

condition:
	$a0
}

        
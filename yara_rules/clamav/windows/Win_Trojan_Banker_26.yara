rule Win_Trojan_Banker_26
{
strings:
	$a0 = { 10f38e57e65a72100b47a01f44d403d34d1db0041b0e7d9f258abc11ee00c2f2389f18a3ef25082e1fc54513bc429a09b24452f234106838d09809792996e0efa6e5488813c6f5125bf021810dc8938c72e312f7f00dfa1a645dd08a7a026137434b64536cea588da011987c2639e9083b66fce0fd63f78721d6aa3c143789b5a139dd8cc3286720ce748a00059569d2b54ab99213 }

condition:
	$a0
}

        
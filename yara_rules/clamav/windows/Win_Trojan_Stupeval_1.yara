rule Win_Trojan_Stupeval_1
{
strings:
	$a0 = { 2f5570746f6f6c732f436f6e74726f6c732e7068703f696e666f7265673d22202620245043494e464f }

condition:
	$a0
}

        

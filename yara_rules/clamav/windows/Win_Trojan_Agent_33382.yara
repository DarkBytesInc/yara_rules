rule Win_Trojan_Agent_33382
{
strings:
	$a0 = { f5e648e5db3cfed54c6449b89e24da0425944e4c92cb6106f51c7c8ae84c7eccc786fcbdf4ba475627c4886f779994bdeabb465842e3c18009726c0ef1c397cca4a09b5bc1169eb0b29efb4af6ea1e647a9afed5ef8361892bbe7d82 }

condition:
	$a0
}

        

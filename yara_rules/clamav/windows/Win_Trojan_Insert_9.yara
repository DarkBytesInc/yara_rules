rule Win_Trojan_Insert_9
{
strings:
	$a0 = { 6563742822776f72642e6170706c69636174696f6e2229 }
	$a1 = { 2e6e6f726d616c74[0-16]742e7662636f6d706f6e656e747328 }
	$a2 = { 2e636f64656d6f64756c65 }
	$a3 = { 2e696e736572746c696e6573 }

condition:
	$a0 and $a1 and $a2 and $a3
}

        

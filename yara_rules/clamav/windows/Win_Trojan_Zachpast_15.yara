rule Win_Trojan_Zachpast_15
{
strings:
	$a0 = { 6578706c6f72657200000000696e7374616c6c006175746f72756e2e696e6600??????83ec54576a01ff1500104000 }

condition:
	$a0
}

        

rule Win_Trojan_VB_519
{
strings:
	$a0 = { 4d795f446f63756d656e74730077696e6c6f676f6e000077696e6c6f676f6e00 }
	$a1 = { 6d00730073002e00650078006500 }

condition:
	$a0 and $a1
}

        

rule Email_Trojan_Trojan_945
{
strings:
	$a0 = { 5375626a6563743a20557267656e74 }
	$a1 = { 49206e65656420746f206b6e6f7720696620796f752068617665207468652070726f6475637473206c697374656420696e207468652061747461636865642071756f7465 }

condition:
	$a0 and $a1
}

        
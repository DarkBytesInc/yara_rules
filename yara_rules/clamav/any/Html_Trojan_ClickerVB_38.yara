rule Html_Trojan_ClickerVB_38
{
strings:
	$a0 = { 8d4de8ffd383ec10b9080000008bd4b89c2140006a016a68890a8b4ddc56894a048b0e8942088b45e489420cff9108030000 }

condition:
	$a0
}

        

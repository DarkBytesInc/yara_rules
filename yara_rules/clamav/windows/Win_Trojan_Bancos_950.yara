rule Win_Trojan_Bancos_950
{
strings:
	$a0 = { 7da9c8c3e65789c98c44af5c44b9dfe0c884599c5b0d983fd0177fc34dd75ac9a4702ed582d6dbd3b28e2079a781e1249e9ebe30073d85d64fdacee0f3989c3d079fe00c13e1929c45cb209926996266fd9c }

condition:
	$a0
}

        

rule Win_Trojan_Bancos_1024
{
strings:
	$a0 = { 8271d634b4beda2b6e2e434bf0034613944810300de2585138efcd003afa2d89ce0ab9ce28de34303dfdaab75366fb5d7dad35c9e2465ab99db402c88bb00b302fae0235ec28d453501dd4f7bf591eb3b169714e55 }

condition:
	$a0
}

        

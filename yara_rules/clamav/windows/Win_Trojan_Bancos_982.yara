rule Win_Trojan_Bancos_982
{
strings:
	$a0 = { 649895bac690bbacae8e8f04dcd484d86489426544485d9a909a3c91a85fd9f34c6524be0026ce0ae581ea1ab2efe2a0395feeb4f3703f916f41feddfa27fd687bd4ae59e747a8c1a16388af9815f0745e3f491f8a3fc2e1 }

condition:
	$a0
}

        

rule Win_Trojan_Bancos_1409
{
strings:
	$a0 = { d5bca95634b4051dd915568accd4ef9b8ffecec63662c031bbb21a12d54d97e33c704043f1706284312fe2fb08d47e461e14dccc4ab55553dcf964693007e81aff30986fbb67afa4217a3d30f60ee6243a101b686ef2ab9dda64a8f1 }

condition:
	$a0
}

        

rule Win_Trojan_Bancos_1183
{
strings:
	$a0 = { 52477a5e37768dd85e75374daa222c05b4fd3f456844590ae5654f6f7a6d7cdc7df878b95653a7ea90dcdfe9a5439aa474fe0b8f0b3ece773fd8a39632a955edb8bcbc9edda103605cda3452ffd21e84cdf7bfac86dbcc0f90745e0fe5bfa79f60206b94d0c3fa3d8302ddc25026146d }

condition:
	$a0
}

        

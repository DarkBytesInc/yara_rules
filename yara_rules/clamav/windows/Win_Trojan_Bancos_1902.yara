rule Win_Trojan_Bancos_1902
{
strings:
	$a0 = { 36d02376c346da0b8ebb280aa3ac6be077801df542488b0e720f80a1e3dd17a35c23428a2779dca314212ec2c23cd8016c134afa01dd9d46862fa7d8c71d46114a25595c804f }

condition:
	$a0
}

        

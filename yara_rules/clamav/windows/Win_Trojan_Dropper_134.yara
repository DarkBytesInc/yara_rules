rule Win_Trojan_Dropper_134
{
strings:
	$a0 = { 45c4de31ee8e6f22696495cc26affa5df6f8cadf4ffa7d7bd4f09d4cf4b1bbcedc3dfdeeefefe98cd9a370dd5bac5c72dfbdf7df1bfb7cdc3d71e7512d8663e607963c70e0c154dc4464c58f8faf7ea867c2730f974d7c7362ff23298fc63d7a70d2fc49a726373eb6f1f1d55352a63e3d75cf13d3a63d3e6dd6b4c169e79e4c }

condition:
	$a0
}

        

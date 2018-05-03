rule Win_Worm_OpaSoft_2
{
strings:
	$a0 = { c2c6d61968a23de9e37696ff5c4f1f5c182ecee6d975da46ac0699db76c24d5dc47797e127d406b7af2725e5103ca1d2d6b0705e73a67cb4e573b0ef0cb5b24272cefe417cc9e4dfad1da2b898f859298dabd61e4b52ad9956fdc9d0a5ce55b1661ce577 }

condition:
	$a0
}

        

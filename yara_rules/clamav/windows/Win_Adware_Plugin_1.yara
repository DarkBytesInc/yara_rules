rule Win_Adware_Plugin_1
{
strings:
	$a0 = { 8d8d94f7ffff5150ff3500690310ffb5b4f7ffffff761c685c4603106824080000ffb5bcf7ffffffd7ff7624ffb5c4f7ffff683c4603106824080000ffb5c0f7ffffffd78d85a8f8ffff508bbdb8f7ffff57e8d2b70200683446031057e8c1b7020083c4448d8594f8ffff508d45c450ffb5c0f7ffff57ffb5bcf7ffffe800a80100 }

condition:
	$a0
}

        

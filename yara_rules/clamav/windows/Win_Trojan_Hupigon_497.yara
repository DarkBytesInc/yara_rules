rule Win_Trojan_Hupigon_497
{
strings:
	$a0 = { 39be66425a1915a4b2eb26ad31620262c1a0ba15fdc39b51aca5b6bf6f5688d9fb4b28dd9913017ae39d4a32e06e0102fd15476e59c0564c257afb404086cdc19ae3c45dc2513d85acdbcb2b415e4752d582c7e8c7bc77e2f5a09fe6b1c6c8df5e79ec78 }

condition:
	$a0
}

        

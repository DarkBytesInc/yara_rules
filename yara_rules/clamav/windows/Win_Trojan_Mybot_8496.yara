rule Win_Trojan_Mybot_8496
{
strings:
	$a0 = { a149edbc7cea3e72c54fc005904ff9f6388c844dd203f14f5cae2b329073b2ff2047efa901e4ecbfae2a3b4cd7f0c01cc52b65809e3c3d816eada389b4626dae1cf881c3daa6b27fda570f4c270175c226f1480cf9 }

condition:
	$a0
}

        

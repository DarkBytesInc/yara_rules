rule Win_Worm_Bagle_195
{
strings:
	$a0 = { 8ee5f94e8f3840cca6159ee8e233d51aa81237a65828dba27cbd274ed3d723e4f52feabf3031675bcb1bf6811f1858f9064fb4ecd30ba3eb63b9f6d4d3f6d90826f6ed872dd1cc94f16f4dfaa6aa2b68b0d270f413e55de3128fe65e8a801d0e }

condition:
	$a0
}

        

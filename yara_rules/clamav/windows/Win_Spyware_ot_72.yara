rule Win_Spyware_ot_72
{
strings:
	$a0 = { 4475d13516756db6b8bf1b3f8a6d92da20100fdba8bdc1d862deacfbfd1e1d57a7aa855debed3aa0a84e8e9ff47d194862b73f4141d543ef4a556c5236ffdbc287d111daa6a74d53663c372d37d6eff366a8a88f14af0cb68aedc806e30b1d02081e5e78c52a10379b882c6a36f5bdf279ba02be9d96b55b }

condition:
	$a0
}

        

rule Win_Spyware_300_2
{
strings:
	$a0 = { fbc65b7fbf5c9cf6e1c6ca79aa87b39467d92279433cc3213f3fa2ed04b1998c7ab4eb2d1c94526b9b0e3444bca7f0e29537217e3d58f4a69b83ccbc87fd34aa46b67432ba3aae39d582f9df1fdb90217445e7eeaa1a3a79614fcd2f5a23a9 }

condition:
	$a0
}

        

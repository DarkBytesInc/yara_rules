rule Win_Dropper_Agent_33658
{
strings:
	$a0 = { f3342c52f45668f962ded00f58d809c8fe686b5a1d4ed8e7a1e44fbe668dc7b6df41fae423c38241c6b3a0fac1dcf4d7c5ad6c1a85d981b01fdebf23a18169fe6ec9f150da71779d6a9a473c8d256478 }

condition:
	$a0
}

        

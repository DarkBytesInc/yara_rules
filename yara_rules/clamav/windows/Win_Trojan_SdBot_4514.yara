rule Win_Trojan_SdBot_4514
{
strings:
	$a0 = { 088385184b6cfce3cd37d1dec06f61937e0fd6819c3fa487bdb773f1eee5897de4f126de7599daed4030a62e1c8920efe402c7e1976adfd5d03e5f2c3eb38c590c07897d7077a27cbb8a26aa31bf86e8a82273c4a55b539c7c9ca2019523b599432bdc9de4f6f40897d5d85a0d1a7f02f216cba2a141cc38f8ab96ded8f0f61d921f9c84e636da3f244fc2a0 }

condition:
	$a0
}

        
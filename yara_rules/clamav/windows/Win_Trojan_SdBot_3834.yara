rule Win_Trojan_SdBot_3834
{
strings:
	$a0 = { 50ee3a00a3506d58f01fb37742e85d68ad8fbe3f66221ddfe3aa7eac49ef33b9c5306f6073eded5d1d2ed65d0915395bd18ffab7e614a783d46cc7e2c504967e6f982c29f54ce727cfb3c27fbca991f9f9354e788d10918cf4ba98cb5bde33c69874 }

condition:
	$a0
}

        

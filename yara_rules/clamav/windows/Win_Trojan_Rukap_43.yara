rule Win_Trojan_Rukap_43
{
strings:
	$a0 = { b8984f5e53bea37935c5f26ceaba8941442ee4819efe28258eccd1820d167d6447c6a50ada5e41ffcb9964ef4e856ba16a611d1013b5cc7eba741c1f8fd3aa992383fd219d33504e3ab5e96f1bfedee0c0896ca72cea619698 }

condition:
	$a0
}

        

rule Win_Trojan_SillyC_143
{
strings:
	$a0 = { f0400ae06a80fc44f11348addedf49dd69bc49d712518561a3942e433a337601fc5af288484d69c77bd97bf285018bf9750762ae2b672540d891904810 }

condition:
	$a0
}

        

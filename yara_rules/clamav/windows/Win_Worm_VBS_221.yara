rule Win_Worm_VBS_221
{
strings:
	$a0 = { 726163696e65202620225c616264732e76627322 }

condition:
	$a0
}

        

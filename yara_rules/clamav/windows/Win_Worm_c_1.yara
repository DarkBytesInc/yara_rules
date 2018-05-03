rule Win_Worm_c_1
{
strings:
	$a0 = { 0a4563686f20492e53656e64203e3e205c424f5474776f464143452e564253 }

condition:
	$a0
}

        

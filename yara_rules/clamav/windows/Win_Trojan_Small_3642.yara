rule Win_Trojan_Small_3642
{
strings:
	$a0 = { 3f134129c29de2523bd5dcd1af7a1b99ca23e898ca23e898ca23e3545e97e25c5e9be209be53cc147455cc10c4d45949be53cdfc8d1d713bfacd3218cf53a0635d541b99ca23e898ca23e34c5e97e3d0c4a3988c0c }

condition:
	$a0
}

        

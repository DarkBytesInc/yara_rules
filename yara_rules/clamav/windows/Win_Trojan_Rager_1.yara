rule Win_Trojan_Rager_1
{
strings:
	$a0 = { 1e06e97f0290909c1e06603d9999750861071f9db87740cf3d004b7405e9360290901e560657e848025f075e1ffa33 }

condition:
	$a0
}

        

rule Osx_Trojan_MSShellcode_34
{
strings:
	$a0 = { 0200a0e30110a0e30620a0e361c0a0e3800000ef00a0a0e1010000eb0002115c0a074dba0a00a0e10e10a0e11020a0e362c0a0e3800000ef0250a0e35ac0a0e3 }

condition:
	$a0
}

        

rule Win_Trojan_Symmi_4
{
strings:
	$a0 = { 5052c60564c65300018b4d08890d68c65300894a04c7420800000000c7420c00000000e8c1ffffff5a58ff356cc65300b9c0704700e85fdbffffc3 }

condition:
	$a0
}

        

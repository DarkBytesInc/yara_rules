rule Win_Trojan_SillyRC_28
{
strings:
	$a0 = { 78012e891e92012e8c0e98011e06b810008ec0bf0001be0001b90800f3a775138d1e9c01268b078907268b470289 }

condition:
	$a0
}

        

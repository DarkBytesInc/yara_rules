rule Win_Trojan_Hupigon_836
{
strings:
	$a0 = { 0614955cd5855236ffe5a4bd7fefb7c90223df5429f8385079f245700bffec53a63030ca3d27301347beaf405fabdde7e34f32b5fc49192caa4957784105a0f0ac5af74358ffacd6bee391514fdbdad37e3b5576e9afc3c04a7f8fd73e04e1 }

condition:
	$a0
}

        

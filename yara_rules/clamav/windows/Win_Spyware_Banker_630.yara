rule Win_Spyware_Banker_630
{
strings:
	$a0 = { 110584b902d08e195a9821c1cb81a22c821c6eb14bb664600b4659f748830000f6c5fa1cf006b391982238256b755fc1f8d1d3ed861e301043085aeadb98d6b42b030c6426d43a1e64d84fb3a6835009e082d35e9f3490e19bb5303b321729224322814757c997f0bf88e9c423f5923be725a69af8815ad7a2802f884233142343239d29192c3f8f9755b6367185b22f8b984816cd02 }

condition:
	$a0
}

        
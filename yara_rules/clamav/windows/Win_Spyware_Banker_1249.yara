rule Win_Spyware_Banker_1249
{
strings:
	$a0 = { c8492a1263c8e31c5f55d90fdedc57eda65a0b54b3960100c083c0d97cb0671db748a4c3313fb0fe75cf7d637439cfa9c5232401c27a3341f00d0a2d20bebf3d55c9f48ede7b381b919a214c31e4d34bf2fed18abfa446d9147aa6c660418a8ccdb61a6d }

condition:
	$a0
}

        

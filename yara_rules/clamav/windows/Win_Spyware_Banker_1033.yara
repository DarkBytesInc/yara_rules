rule Win_Spyware_Banker_1033
{
strings:
	$a0 = { 17ce7cfebaac594f29cc295a541dd8d11098228273354a2d91246789ed4e62ab86a23a7487453a84c67eafaaef55c70c0652235daa5d53bbf8a1843764fbd9fa008b4227e86af72522973f830af108bef54930b41e4aa70e0f0bebff9e95b73dab0693d213d5fff12f480517b84fa643a1d7cee8576a2393346df41fd306b4a67c6dfc4c6da1e633fc12bf23ff863b9a4fcbee68f5fe }

condition:
	$a0
}

        
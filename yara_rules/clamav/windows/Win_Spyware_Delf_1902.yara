rule Win_Spyware_Delf_1902
{
strings:
	$a0 = { 9a7d0d5c5455faff9d990b0c383aa362be61524d25a10562090ee6080c22be8dbc89281a0984c6aa3fb8572c41861dd8b89c28b6addd76ebb7ab6bedb6adbf8db22d7ad96d6008245d457415c3d2b4ad4bd78a84d551c9f93fcfb96706b456ddbf1f87efb9e7e539cf79ce39cf79ceb9e79ccb9bac9c2e2861d3a6e282 }

condition:
	$a0
}

        

rule Win_Trojan_Mybot_8463
{
strings:
	$a0 = { b5da6ca1e20e789528d30325e6f614d8f3e8eb3b5e7110dbf1dbde955fa71fdc128f45b7e60ef875c923eab28bc0fdc5c0637804740234e5d635f273331fc0a0655fa4b4fd286f5262ca88e35985e3540ce3f924cd }

condition:
	$a0
}

        

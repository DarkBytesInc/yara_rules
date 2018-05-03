rule Win_Worm_Gaobot_28
{
strings:
	$a0 = { 4e4382a0538a19e3aab15170dff66a8b46dc8a1c4c8d6562a0641a53c416222e3a50bc3def4bd2cde540a64177617f79b29ab3feb6a25e99684ddeb2c83d6e2838545959d37d84b1 }

condition:
	$a0
}

        

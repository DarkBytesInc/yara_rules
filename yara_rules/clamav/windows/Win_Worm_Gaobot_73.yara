rule Win_Worm_Gaobot_73
{
strings:
	$a0 = { 4e4331689528f3f8e2854342a8b757c054cf928bc1eeecab9114866d94c4e968c8f02fedf1ee7dbb9ac3719409cb8e42 }

condition:
	$a0
}

        

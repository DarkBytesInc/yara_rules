rule Win_Trojan_Spambot_120
{
strings:
	$a0 = { b863220ebd418fd556cff99295553db2cdd040431748ffffffffac34c14744bc6091c2ae7dadc1f29eba081f6441962f678f8cd707b6479c868470ffffff9588431f0d2057e4bb1bf329fb4e6927f16609ce3fd81db0d3ffffe0ff5bfb0f938b4dbc016b0d4962db0a6b3833783a }

condition:
	$a0
}

        

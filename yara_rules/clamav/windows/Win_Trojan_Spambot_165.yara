rule Win_Trojan_Spambot_165
{
strings:
	$a0 = { bd3fc5ddefe536dcce375f944e891fd55f7cff1fffe0d3dad481b45449b2df56e5a5d94d6684621f5e0eff8fa8ffa8d44236783e773d879da4374eafaa4e6ddf4dabff9fd0c7e10683c69d512940d39cd23b6243faffffff56297420b8e7b383efe075239b8c1c38e67c83bec98d }

condition:
	$a0
}

        

rule Win_Ircbot_Fedex_1
{
strings:
	$a0 = { e878fdffffb9f0ff4400bad0ff4400b8e0ff4400e864fdffffe88343fbff000000ffffffffe80000002f2f2e6c6f6164202d727320633a5c6c6f61642e646c6c207c206675636b6572 }

condition:
	$a0
}

        

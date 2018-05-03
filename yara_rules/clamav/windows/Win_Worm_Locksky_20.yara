rule Win_Worm_Locksky_20
{
strings:
	$a0 = { 68edfdbf00ddaa13ffc471fc3005d2bf74026c983005d2740d60e2bf00dde6ff00c5b5c43005d2003538e2bf00dd5e13ffc4573f75e12dca031592ffe8143e00ff5da6ce40c5359eecc42d17d83bd2ffe81ed6ff00f85bf2131592ff6a39baff }

condition:
	$a0
}

        

rule Win_Downloader_Swizzor_583
{
strings:
	$a0 = { 5b0a48433dfe0a1bc535558b1b886d1f951bef66987284eb012dfd6455047d5e23ac5d2af689a16cf3acb91b31ddbaa4db215bd22cb615b8dc54c7f34086dde2a2b9a00926442d565cd46251996b27393db9baac44c8b3a6eef0f7fd49b0b14b18c0faad23e22dbbc3 }

condition:
	$a0
}

        

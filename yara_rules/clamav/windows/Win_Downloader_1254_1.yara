rule Win_Downloader_1254_1
{
strings:
	$a0 = { c9c9c6850afdffff33c6850dfdffff6480e27580c6bac6850cfdffff2ec68510fdffff00c68506fdffff7680f11f80e5e9c68505fdffff64b22680ce1a5583ec0480ca7f8dbd04fdffff893c2480ed07b2b6ff15547301105d89856bf9ffff8b856bf9ffff898527feffff80e145 }

condition:
	$a0
}

        

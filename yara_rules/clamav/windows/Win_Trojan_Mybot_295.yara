rule Win_Trojan_Mybot_295
{
strings:
	$a0 = { 0f3e6ebf6875a9d5451e2a3d7dbaf23b6d24451c27ad69ee454f80304156454e53487549284c449acb61837f727687b3ca1c323054334078 }

condition:
	$a0
}

        

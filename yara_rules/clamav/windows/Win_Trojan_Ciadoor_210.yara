rule Win_Trojan_Ciadoor_210
{
strings:
	$a0 = { b302aabb94b3b34ff5ae0228b22ab3c3d3b2aa5394b3b34f9a2adefff2b22aeefff2b2aa2c94b3b302aa2294b3b349f5622afefff2b22a0efff2b2aa0494b3b302aa1a94b3b349f5662a06fff2b22aeefff2b2aafc94b3b302aaf294b3b349f5722a12ff }

condition:
	$a0
}

        

rule Win_Spyware_Banker_2996
{
strings:
	$a0 = { f3aa85425b58d0f3ba6bc647bbae71d07e86d0f47c20b79d72b9ce333e61cf5ae7c4d2926a5eff2ec80cb7b9ecda9bcbf7515f289fe5ce030614d3f598dd2ee05a2677b488e7a861fbf98a18f399678ba00e011207beb4f70cf989047f6a50c9c801d050 }

condition:
	$a0
}

        

rule Win_Trojan_Mybot_4841
{
strings:
	$a0 = { d56bea8ee050a4394ba31ee17d7bc8786d79426f741d43ad652db4f702df7a74726f6c3afd2d63222c1073aefcff730c116d61782d6167653d300d0a70721d053accd6497a6e6a }

condition:
	$a0
}

        

rule Win_Trojan_SdBot_4529
{
strings:
	$a0 = { 75e131a430a2f24cbbd09bd8bd0aa891f6a77d639131f66ae7748b2030a009baa388ec499a997c2eb49b8b1edbd00bffd56bf225b154dace7fe8ca622282fc35cd0a35d0748fbb0496948b16f4e4d54ce350c63d23d47c22ad8064eb918f02bab911148ab4c5c4fca827ee68d53704e996fbabc695771e947d537f7b9b0509234d3a72c130a4f82ca323feb9 }

condition:
	$a0
}

        
rule Win_Worm_Bagle_176
{
strings:
	$a0 = { da86f3320a07eee0cc0ecb83404531bd921f076eb9b2b655101fc2eb724d5357f3f21a30ac7a545d3e82228b50516c392cf1bcdc8048a8f91b133f2a4b30eab48661695e5d0c8df3208e3382a8135c053be0b1383e628bba7be48c47a34f078b9e6eba835c454820e8d8ac1a8b9a6083b92b49492e874b78d68264ddf15ae09d4a292941 }

condition:
	$a0
}

        
rule Win_Worm_Delf_2115
{
strings:
	$a0 = { 575f77ff330c77696e63666773542e26707f6ef7fa7952756e4d21254f0f4b423230208865f730363031015501937e }

condition:
	$a0
}

        
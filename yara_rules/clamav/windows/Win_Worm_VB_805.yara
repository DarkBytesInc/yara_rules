rule Win_Worm_VB_805
{
strings:
	$a0 = { eb7d0f5c54d795ff03469d182268c06042924942139ba845c10415934119a391d16160d0a41a456670400432cc28a6d290021ba6cf69488bbb746b7e3fdb65537f2ddb9fdb9ad6a46443221be8fee8966d58631bdad22c6d9f955fcb3636218dcdfcce39f7bef7eefcb3a61ffee4976492f3eebbffcebdf79cef3df7ef }

condition:
	$a0
}

        
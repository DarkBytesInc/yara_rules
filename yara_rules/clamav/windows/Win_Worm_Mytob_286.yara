rule Win_Worm_Mytob_286
{
strings:
	$a0 = { c3df7cec2427da031c323f9c99ca71adbd702aece9f43381c25f748d5a59bdffc2be5960ed40081c4c40c233db432f5b7351a528651ee98319f1abd0afe3b602e6d30db7b6af79f9b102340a91e5509fcab7e2978f5adefbc6b961de425dc56e }

condition:
	$a0
}

        

rule Win_Worm_Bozari_1
{
strings:
	$a0 = { a82bb2b2e7227abbe4d2ea3d7f7f60202db091c083007d0975e92da6476e4dcb87d20c917ccbc5016f8869b0558752bf6a272ac17b2e348ea6a5dd8f24d6c4dc7401e9e1f684c7d6daa579feae35c1f7f0daf9afe3d600b4fe51d09baf303721634b42aae12656a2fd62526839bfaafb }

condition:
	$a0
}

        

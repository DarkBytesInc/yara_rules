rule Win_Worm_Lebreat_1
{
strings:
	$a0 = { 14de90ccff4587737d5ef2a544b5dd2ae48f317a79cbb7ef8b4fb9087d92843545d560c8188c244bc392cc6a77245108766700defcedc9ebf61cfad8fd7b7a71ea3199da0cf8ede68c121dd8fedc3fe1f04c376c29aed56ef60a9f9ffb3dfe69e03012644a6d0fb17cb354f2618624fb }

condition:
	$a0
}

        

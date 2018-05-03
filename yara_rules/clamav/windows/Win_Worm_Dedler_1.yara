rule Win_Worm_Dedler_1
{
strings:
	$a0 = { 81162b6ef943e601f790e79b91b6b35e5bec98aa061a38c3144278dfbbe9fca6eaf41739f6ab60803f9f7dcff7a30e224680cc7a83c61b41ca678728946d25b2989c131e31c352deb997b7b60e10a51e9f60b5b05ffaa1deb9e0d1a86f088fde }

condition:
	$a0
}

        

rule Win_Tool_W32_1
{
strings:
	$a0 = { 5e5bc300ffffffff0a0000004e756b696e67202e2e2e0000ffffffff060000004e756b6564210000ba745642008b80bc }

condition:
	$a0
}

        

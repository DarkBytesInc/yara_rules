rule Win_Downloader_Banload_1059
{
strings:
	$a0 = { 8de08340d7e67276662c32369cf7c8b788daa52a675eaeca70ecce60967219e2a74531fadf3ce2808edea6c3dc02bbe9152c6c135a1bec3aeadf646b1ce7eeebe63fadb88199678ea3292bdb6c7a785e7c1fba2bf4bad0589a61c75e2b49524a3a234d432ff778b6d5b0ba74012f9e72768f9dc2189a3cb7 }

condition:
	$a0
}

        

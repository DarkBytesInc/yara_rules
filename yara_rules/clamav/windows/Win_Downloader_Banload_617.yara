rule Win_Downloader_Banload_617
{
strings:
	$a0 = { 9b1364f4ed90c5fbb2bbef31c62c81fd04c04c90e643a891c57194442b4438d70299b84d2207b13b3fef6cdfd77f1c6662736c1c27a19c7831cae544fc72dbe9f40ef822e5949cf99067bde94fefdd9fc0f9b02456deca2578b7 }

condition:
	$a0
}

        

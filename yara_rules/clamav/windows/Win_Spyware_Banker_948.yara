rule Win_Spyware_Banker_948
{
strings:
	$a0 = { dbe9e92b6344a5314f01dfda77657f0b7bac43a47e52a7ac1d04f4a7e8466c2ad61d7eb740960c685d4c597ed089c2c80adab6d3ef68eaeacb93fbf3f9e8ed09db215e2b3d7c5642e4d83d91dc161ef62fea6140ba74a30a3eee046ecc32aba7a701d9fd0302c2b3d585e35858ee10c707cb35d1f1fecde2e0ea4d261c1a622c }

condition:
	$a0
}

        

rule Win_Downloader_Agent_31814
{
strings:
	$a0 = { 4d39ecb80be27cb450c9caa610f8d4d21685449dd0d40ca654c968a5173fd4fe14811b69c43933a6ef03362a63c11e455c06d4f1a8cb97f716e6e8bb0ba9c6fd247a3be111e6fceb5a6a7cbc0ba4cea6510d611380d22e4e480fd4339e73 }

condition:
	$a0
}

        

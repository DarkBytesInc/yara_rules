rule Win_Spyware_W32_30
{
strings:
	$a0 = { baee7ad8b68f4aca37bc6a02f11b5e79bd9dfa392b74b99854bbcf4b8e163eeecac594a36c6b75629d4fc3f776714ebfee7e7bb1458803f9bc0396b4c9fb8546cac1fd7a6c2560f3fe6efc6ffba40413e6ae97dfefebd90cb9f7a18f1459d6cf9bde9209f3ead16d7f071f95ad50a013 }

condition:
	$a0
}

        

rule Win_Spyware_Banker_3499
{
strings:
	$a0 = { 3dec729fc4c5fb55dcc65db1922e37b23ede6b7b707503be4ec6fabe9af0e95a0e895621bff5da15f3e0470cf4f2499f8fb57a1ead30fe34ef5e26500f41b2b93a9b1a0c67f1e3f742eb8529cd5a1ded776c9683b22689ebc52d58a7aea4faefcc420b407ed3eeb02ff0b73f5f82091c9ff2934f9b2a }

condition:
	$a0
}

        

rule Win_Worm_Anset_1
{
strings:
	$a0 = { 3bd67f03564e3bc606d743abbb275b6c65cb777a654ac3a05fd7f8ade85881f6884e9aeb05e29f5abc0c661cef802327ebb69c8be8e0bbfa00ec1945f12570038803183d9df2698c0b44ea7f1a0e2bc2 }

condition:
	$a0
}

        

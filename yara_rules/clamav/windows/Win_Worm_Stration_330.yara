rule Win_Worm_Stration_330
{
strings:
	$a0 = { 36f92336fdfdcbf9c053f067c5be45a75d69802f738b94baf8a7bcab1ceee96c7ca0675158fb03a8934de63fc47e72ac6bf86b91eba0e2d8f074de9a5095b7cf10da99b977daf3ef92355c9d465263ae }

condition:
	$a0
}

        

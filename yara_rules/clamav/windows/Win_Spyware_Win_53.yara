rule Win_Spyware_Win_53
{
strings:
	$a0 = { a27b460d845c2f19639c36285460dffdfffeffc21ccfb9dcaf8eae5db6aa424fa02fdfc5521f1ddc024148011eefffffffbf18572f73f11f47bff1b6b33aebef1e9c2d81d3ce668237936c7b83945f3072ff7ff0ffa7b738fa5335cf89da42c1e2599d5545edcc163f65648241ba44ffffffff }

condition:
	$a0
}

        

rule Win_Trojan_Bifrose_171
{
strings:
	$a0 = { 0fb2069085802d56bef58100ce31f35e8c409ea300fce94be7952c170e38a2d43eb0895c528300799ffb023200d6e2b24682a517f839f75b80164ca8f40e32ef00500bde }

condition:
	$a0
}

        

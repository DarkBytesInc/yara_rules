rule Win_Downloader_Banload_254
{
strings:
	$a0 = { c0e937dd224692ad12a921c54b6cbe10575802ef63cee393f961d363dd0118926897b94c7758c9cc5b13b03bda8fd4f35d5f11ba935d3b2a9c3cc40a8405ae5193de85502bbc9decc0c9a410e21cd215b5facfcc907037d2ed60 }

condition:
	$a0
}

        

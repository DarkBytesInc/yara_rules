rule Win_Downloader_Banload_830
{
strings:
	$a0 = { 9eba794586548c80f0ac893d678e5a18c5c036ebda9fb660af2681bf4b31bf191cca368829a826721c74e43404b4f314135fd5b9eaa0eac239d8b93cbac907fea450631f40cee9563ac56410e9c65956f0ca29ed3e962ffce94d }

condition:
	$a0
}

        

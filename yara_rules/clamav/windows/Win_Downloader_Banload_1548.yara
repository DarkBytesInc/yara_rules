rule Win_Downloader_Banload_1548
{
strings:
	$a0 = { 3f4a0a4c948bc35c932897e7eafe66d445219cfa87dd772b2267f3cfb4125c6c45a77c4395b935d18933a637c14fa90da40d9934e1a0bbce6cca073a52e91d562d5c5b177195f574e6d16acd67e43107f0565a0ed5ce74f05c3a }

condition:
	$a0
}

        

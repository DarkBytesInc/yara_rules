rule Win_Spyware_273_2
{
strings:
	$a0 = { 5f125cb1dc0da3caca67ded9482705265fae778c2b8bdc2abd73a7b1dc0da3ca482397d9a098c1d1c81bdeceb38f91faa067dcdcbe73a7b1240ba3ca484f97d9a098c1d1c8e3d8ceb38fbdfaa067dc59cb70a7b1dc0da3ca48d306265f6c74ada98fb226 }

condition:
	$a0
}

        

rule Win_Spyware_Delf_1837
{
strings:
	$a0 = { 74812710017f2e6d6f6c28060b03040a626201c00a035313353f2134541b3c3829c6801156836446470129214d91c4e0c3c6a5740b03e08431286743584e4d4c5a233004e048a36095dd44ce8a25be13546c821f03406407556e729bfd074652066874e7ad8f8387b05c586be3237861024d44d2d185a1c0059385b674 }

condition:
	$a0
}

        
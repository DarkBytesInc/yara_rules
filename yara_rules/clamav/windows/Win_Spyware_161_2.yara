rule Win_Spyware_161_2
{
strings:
	$a0 = { 566d28612a49d69589e3004e4b5b6a4af2cc1d304fd10540ad2f5467b9e38760b3ebd4428f9bb256e6c7aaafb5165a922405365de59bed353147203e788dc71df147c263901497432531d5fdd523dd541c807e0fa23302e26bf64e13e689 }

condition:
	$a0
}

        
rule Win_Spyware_152_2
{
strings:
	$a0 = { 7c82a00542026aed5af1ea687350816dd1f0c3be502943025fd1afec5f2be4cb597b7d63564598367e465fefcbb336434b57332a1309d112af3fef1ea208b613b86fa5f714cd5afa9a8260845493bc942038b1dd33f18246790d12088810 }

condition:
	$a0
}

        
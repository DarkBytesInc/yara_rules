rule Win_Trojan_Joke_4
{
strings:
	$a0 = { 3698106619a0006676fe0e66a79a0c667c9c0d66138a0f66a5990c66a43c0e6609fb0e663af80e6603580d6653751066714f0d66ab880f66eee30c66af9c0d66baf70e66baf80e660e610e66c5600e66875a0d66eef70e6629f20e667c350066366e106640870f66f4600e6675630e666de30e66848b1066c48a0f6691d10e66b0600e66279a0d6600000000 }

condition:
	$a0
}

        
rule Win_Trojan_Worm_49
{
strings:
	$a0 = { 591568c450db4362cc51b4d0625254483e2aab244db83c5665c4babf813657e2d8ef805d82064702d727fe40c706b5fb5a67dc41a526889879777c9a758a36736f6da100e45f6ed79c53267e5ed391ef313405b8b9b91e99d65ed5b68c818287 }

condition:
	$a0
}

        
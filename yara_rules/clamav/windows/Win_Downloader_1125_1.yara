rule Win_Downloader_1125_1
{
strings:
	$a0 = { d8ca0f20c9a6fa6c2f6479c2614ab2edd2ee490ff88ceea44f2d0ca9234bd31c276520e9ae3dd9b68a671eb15c7f231dc29193a5672325c5aa81e22cf5e727fccd3cb1f3611fb4e6a48ff6288a244b86d45701349126b4c48a663bb2 }

condition:
	$a0
}

        

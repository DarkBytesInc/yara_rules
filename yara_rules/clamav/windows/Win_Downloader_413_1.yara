rule Win_Downloader_413_1
{
strings:
	$a0 = { fb32397305ab53eaba4e7bf1a5aa4b3ef3324f3e336bfdb0a59fc6b1a5364fb01b3ffd812bf772e532bc32afa53666b1a636fe00a5ec32b0a536fd26ae3513c92277fe3566ab133e2b6bfcb0a587fd26b23513edb676fe3beb42c774d9f6c774fbc1ea32925fffb0a58c551ba6a000b0bb5e7bf1a5c1 }

condition:
	$a0
}

        

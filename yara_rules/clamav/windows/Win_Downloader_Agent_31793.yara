rule Win_Downloader_Agent_31793
{
strings:
	$a0 = { 48344c04d49224efc73c511c17073ec273bedc743fbf99a91cea024ac4bd9354c4abc2554c0be248cda03fa4cda6b9e34dafc351cda4eb53cdaaecf27747df56d8ab9c5ec4a9c2cda269ed58c4b1c259cdac6fe79a451c5b3792dc66db937890af31aac19e91dcb4e2696d2265341bde6494dfb1cad260bb }

condition:
	$a0
}

        

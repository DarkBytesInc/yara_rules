rule Win_Trojan_SdBot_2013
{
strings:
	$a0 = { a72b2d4ab1a1565b65790722d852218844cdee6649b8d5aa37d786bbf51dfac7bf541b6f6c1b7b7b200db2016d90042416d33222920953b2029a82b4d64053522b5d48faea02d752029a91f43520b6e8056ea487a6a02dba3d15d0b6f2eade5ef7f7ffd53bfdf3e79ffe9e6f7e6f7e6fcdfdff3dfe534271adb8921c3061cdf110c2c5c25fab4d68830c016b }

condition:
	$a0
}

        
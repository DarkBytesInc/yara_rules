rule Win_Downloader_Small_5095
{
strings:
	$a0 = { 1f5d24d130474f23bd7d275f285d465b0b08ec2cdeb36a078e0e5609eb04118faeafa958509756ec529186353d7341635146565d3e1b8417a3d5091f44482b308ca014f69d0d43d0f066188a063c5c1fc48750e035431a1c1d114a3fd6a275baf107d912eb0e3c207e6d40fbb10a0a803e207ff6225e0f44e205bb137f0b312d4dd5d09c743c381cf605010f4e173ee7385f8cb80a32 }

condition:
	$a0
}

        
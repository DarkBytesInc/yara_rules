rule Win_Downloader_Banload_1825
{
strings:
	$a0 = { da0afeae6d94448a70caef7ef33f974f276278da050cdc879d44effb991d612ebbe6665028c006d7d0568c7b2ca0ae8d5386d45786b1de55b3821e10f69d5fab50a9ecbd43a3a4927879393421a151d7569e5e1c06b89773db94e9eb1621a88db2d4dda1f58dc3a65c }

condition:
	$a0
}

        

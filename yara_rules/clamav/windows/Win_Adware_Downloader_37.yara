rule Win_Adware_Downloader_37
{
strings:
	$a0 = { 30cd10863084ba4ddbae283c5ab426658d3e1b27a42418db18472d8fda9cbbd9ddddfda3f4a3ce2ed8ecbcec7ffef6cfb2ca723daf7d8586860251ed1dec23a223d2d3d30d07f113f1ed4f39cc6b609a210c6108759f962b576cd3d7eab830b1f39d1c4e959d0a8d08fd583001dfe5e5ebddd2d7fa3f7fffdffcdd3b557da4ee }

condition:
	$a0
}

        

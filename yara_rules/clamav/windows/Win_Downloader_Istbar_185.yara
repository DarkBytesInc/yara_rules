rule Win_Downloader_Istbar_185
{
strings:
	$a0 = { 3d2573266973747376633d2569266973747265636f7665723d2569266163636f756e745f69643d256926736f66743d2573267276657273696f6e3d2573266e723d2573266e643d25732676696e666f3d2573008681868c85858b89838784838d838a8d8b878e8e89828b81878f8c8686888d8484858788878f8e8b8e8d8f8f8a868e818384818e84858c8e8c898e86848f898980818c }

condition:
	$a0
}

        
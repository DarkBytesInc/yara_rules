rule Win_Trojan_Mybot_5721
{
strings:
	$a0 = { 4866e69d1d499aabc1e25926a2dcd33fb26dafb1c5522acb906e8ad0ad4de49cae59584236b5dbed51dedbdf939d39e9ebef0652d59c28e21020543fd3b3738b6d9fd13ed0ea1c3a17814dfbe84be697ef726213723bb00a4057 }

condition:
	$a0
}

        

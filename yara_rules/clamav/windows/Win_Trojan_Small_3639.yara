rule Win_Trojan_Small_3639
{
strings:
	$a0 = { a6afcbbc559701598f42174119e0c3f616d64d9e6285a614e9cd547eaf6410d74dcc18867c6127ba837770376314d5942ebaf87bac1947441db8c1fb39afbc2ecb15c270b9fab4de845f193bede5641efec6bddca213d78e2041 }

condition:
	$a0
}

        

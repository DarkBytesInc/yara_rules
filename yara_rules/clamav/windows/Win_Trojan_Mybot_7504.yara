rule Win_Trojan_Mybot_7504
{
strings:
	$a0 = { 4c63ee9cc13edee8734568a1de6abcab116c99e1613424e027b048896a12a1106b9ac772590f9466098bc60ee4150dd912884d0809e00c7f14acdf424089051a023de4913223241013e2414636192bc1c314fe0b21fd64fc753170513d2ae9f549b605721481e90a0c2d050a8501188573ec2b83e8c4741ab0dca0e340044e50 }

condition:
	$a0
}

        
rule Win_Adware_Lop_215
{
strings:
	$a0 = { e2f8b6cede1c16ff3befca0f053bfb1dcc218aed1740ead09cb5cc72c31d45621f528e45689ce62f15c6da8e19c193c7159f67f6470fad7b26cbcdab22aba0c5a7bb608b1349392cea920d01bbb2eab14fbb5203bae4627bdd45d30bce9d7e7a069b }

condition:
	$a0
}

        

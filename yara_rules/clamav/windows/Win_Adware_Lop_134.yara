rule Win_Adware_Lop_134
{
strings:
	$a0 = { a43b7cb95465eb48a52c618dc16f12b6a666e1b44fd00d0c0dfe931f806eaed7bdbe48b72562e2e5eac68c6c193c703cd26fa5d1d220ee335500580dfcee22e76dfed6eac5b638b268d8a0c4da280f45ded29462ed329cb1a05a81f275b5cf2d3b46 }

condition:
	$a0
}

        

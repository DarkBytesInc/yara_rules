rule Js_Trojan_Agent_36816
{
strings:
	$a0 = { 3d3833297472797b6461746528292e70726f746f747970652e717d63617463682865676577677364297b663d5b222d3331692d3331693635693632692d3869306936306937316935396937376936396936316937306937366936693633693631693736 }

condition:
	$a0
}

        
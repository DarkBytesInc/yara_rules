rule Win_Trojan_Lineage_498
{
strings:
	$a0 = { 93e4e0dfee9e0d9181a134db29ed0636f25cc2ef56b625f9cea0bb66293e0a7c1c556c289cfdb23afa57d1b39ef7ee67e07b4fd13b391af8145d605b44748040c425e72e3ffc91bf6a66902bddb811c522998dcf78bad7cafc271e647f30d3d149a8 }

condition:
	$a0
}

        

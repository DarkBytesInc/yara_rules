rule Win_Trojan_Delf_418
{
strings:
	$a0 = { 70d7ddee26eecb02d63c0de533ed608b72a0cbc09251cebd3417ad576abcea4630ef3c050c4fc40ba52d374e304e516edd8ac47aed0605bdfc4ea1ed0629d1ebdee807000be302236221f93445f2dbd10b0ca20ea2b9c52d274a27fba95505cf3066911b6a231233b16202b469a0068fa9654b60f26afc8a6f03c3add380d0b0eca8ee77292c5d3c9c3e96b85f607d0df51094d06c49 }

condition:
	$a0
}

        
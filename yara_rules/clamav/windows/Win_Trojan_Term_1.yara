rule Win_Trojan_Term_1
{
strings:
	$a0 = { d311bf66ee53601447d3000000000000010000004d6f64653d227465726d00616a6f7433726d696e61746f72202d2056697375616c2042617369632056697275730000000000ffcc31000243a9a5d4c7d1d311bf66ee53601447d344a9a5d4c7d1d311bf66ee53601447 }

condition:
	$a0
}

        
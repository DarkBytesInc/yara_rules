rule Win_Trojan_Agent_33571
{
strings:
	$a0 = { 2c312377cddeb6b50a377129736d376658b6ec5b133bcf05ebde5bd863132b10db690ec0c00194609a1458232a776f024814e004f14500dc3701b80a0377160746001c0300ee3b00ab72615b00770384b5df1024ffcf440004d00300d040086a2f4b300081f168cf3afcff2fc42f2f6e2e323166612e }

condition:
	$a0
}

        
rule Win_Trojan_Mybot_5575
{
strings:
	$a0 = { 0b338c8d0f097dc55c9503a42056c70c1f05a41456c70cbc24f0520c0cb1b17dc55cb7bc24ec490c0cb1bc7dc55cbc0b95100bf5b0c3c50cb60b33a2cc7dc55cb7bc247a490c0c874800b7a2cc7dc55cbc0b95100bf5e4c6c50c7dc55ca40853 }

condition:
	$a0
}

        

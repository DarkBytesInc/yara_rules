rule Win_Worm_Noverus_1
{
strings:
	$a0 = { 73696f6e5c52756e53657276696365735c53797374656d222c2022633a5c77696e646f77735c73797374656d5c73797374656d2e76627322 }
	$a1 = { 744d61696c2e4174746163686d656e74732e41646422633a5c77696e646f77735c64657461696c732e7662 }

condition:
	$a0 and $a1
}

        
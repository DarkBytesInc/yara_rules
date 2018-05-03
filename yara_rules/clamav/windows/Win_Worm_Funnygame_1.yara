rule Win_Worm_Funnygame_1
{
strings:
	$a0 = { 73797326225c46756e6e7947616d652e65786522 }
	$a1 = { 2e4174746163686d656e74732e41646428636f70796e616d6529 }

condition:
	$a0 and $a1
}

        

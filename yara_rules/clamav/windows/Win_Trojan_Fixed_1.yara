rule Win_Trojan_Fixed_1
{
strings:
	$a0 = { bafb4de001e11ebdceeec6e03ee12c5cf93295e3775944e11e597b32cd0b32e001e11e185eaa79e07c4cd3ad3bee650b834cfe5cdbc33ad63c0b25eea9e001e11e90eae1a7eec683a3fea7ba74ee82e06ce139e001e139ad72e058f1aff16ee3779c8c }

condition:
	$a0
}

        

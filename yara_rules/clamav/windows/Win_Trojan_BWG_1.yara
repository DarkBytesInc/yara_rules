rule Win_Trojan_BWG_1
{
strings:
	$a0 = { 4d61696c2e746f3d6f6c2e4765744e616d65537061636528224d41504922292e416464726573734c697374732831292e41646472657373456e747269657328782920 }
	$a1 = { 4d61696c2e4174746163686d656e74732e41646420577363726970742e53637269707446756c6c4e616d65 }

condition:
	$a0 and $a1
}

        
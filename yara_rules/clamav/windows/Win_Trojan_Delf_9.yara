rule Win_Trojan_Delf_9
{
strings:
	$a0 = { a92c8a3c794e87509441f762d0d4208610ef8a4c29dc43dfc063a62ec36773741201ff2f44686f6c6d2e73652e65752e752a1218e098e92eaf80b93a167fdf0d1b }

condition:
	$a0
}

        

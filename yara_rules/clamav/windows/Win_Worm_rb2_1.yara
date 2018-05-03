rule Win_Worm_rb2_1
{
strings:
	$a0 = { 69662066636f64655b66636f64652e6c656e6774682d3733322c345d213d }

condition:
	$a0
}

        

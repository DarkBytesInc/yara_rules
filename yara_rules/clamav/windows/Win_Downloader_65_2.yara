rule Win_Downloader_65_2
{
strings:
	$a0 = { 985b2f5cec97b9edc60f64ca7da15fbd324ed120f1f5097f1aabda9c1c2afac28402eaeaa963d3256fc90106e1776eb24729d10e12995f230cac10842cc5119e53a3384bf722769b793947e9bbdf314fc535ad1c0e8bec089a }

condition:
	$a0
}

        

rule Win_Trojan_Mybot_284
{
strings:
	$a0 = { 454e534849451a94cd334c44614e4861227263b564a23a097db3864563e44bda458b6029466373ce214d3c41704e5cf64d5ccfeb }

condition:
	$a0
}

        

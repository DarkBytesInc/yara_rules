rule Win_Trojan_SdBot_1075
{
strings:
	$a0 = { 8950816cd13b946ab638d79c6fbf02feece806ca5ceb43b29f1f220f56af22d67292b0f36196b00fc9b60072a5ddcec9a436571d0ee421672923cf13e52344a257edf900349ee02f1e0e3b5d8fb0c38d496fefd1eaf91db3b62317ead4d864a7f62941c2d74334e28b4731f0413e9d01be539b4b1759b8e021c1ff831e2d1880b6eb1771310484c1882d8f84cbc535e2d3819fcf3d65 }

condition:
	$a0
}

        
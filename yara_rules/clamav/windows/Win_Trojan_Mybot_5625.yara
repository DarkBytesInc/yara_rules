rule Win_Trojan_Mybot_5625
{
strings:
	$a0 = { c29c11bca89ec8cb471ec727f9221f212ca077c755560dc961cf38595ac3c1a0dfd83cf1e4bf428b6dd2c5d6ea7789c3c5ea29e2cf36a3a7196cb42ad411f5aae2dd7a5d9059236e24b6d3020e5fd4b3034f92ef0a022e14f02cedef6ea36ec5376cc57d36fde4ae73c6d7efa74c8d6ebcaf }

condition:
	$a0
}

        

rule Win_Trojan_Proxy_64
{
strings:
	$a0 = { 0c5de37347c1d0fa77cbeabb48eaf6fd4db1b8882a30b881e6849fa9e21c9c9339db7af8b460a2957e3cda75e0662b01ad82ba98442b1ed32a06b864481a81980fb31e64aaf0c53e2ae32428c05c17b639770229d0fdca46647cfb2d }

condition:
	$a0
}

        

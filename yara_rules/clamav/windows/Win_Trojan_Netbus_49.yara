rule Win_Trojan_Netbus_49
{
strings:
	$a0 = { 8a7d0b5c5347f6ff4d728100d144c547152bd5d8aaa005d1fa08d62804115f0144f1ad55915aabfee05eb5bf8284465a2e635afadaedefdff6b7ba7daef5b7cbb66e45ebd6402848b516d12a8aad54ddf6e2b5952aab51a9f99f337712d05a5d3f72bf73e771e6cccc9933671e77c29bac9c2e64f2ba756b562e5babe1 }

condition:
	$a0
}

        

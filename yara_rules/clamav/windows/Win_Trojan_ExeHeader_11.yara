rule Win_Trojan_ExeHeader_11
{
strings:
	$a0 = { b81335cd212e891e7c012e8c067e01b40dcd21b200b436cd218cc8488ed8803e00005a7567812e03003900812e12003900be7c0189f78e0612 }

condition:
	$a0
}

        

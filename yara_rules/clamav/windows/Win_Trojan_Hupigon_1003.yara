rule Win_Trojan_Hupigon_1003
{
strings:
	$a0 = { ee595039b7ff6bbdc01453346a6fe3265e8c2b1aaa00ffffbe254493237bb0199eee315d5e4886188318f50b08d6e3316e0ec4c5de5d56dc3fa78efb92cb3ddca6a03f46bff4a02aa97d7c3aa8a9c80f592a96c6f5007ba305d1c72c42cbd33e4d5216f76180d86d1b }

condition:
	$a0
}

        

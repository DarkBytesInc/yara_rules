rule Win_Trojan_Small_3909
{
strings:
	$a0 = { 5589e583ec0456578b750cbf0820400066ad6609c0740466abebf566abc70504204000010000008b4508a3002040008d45fc506a006a0068d53740006a006a00ff15c01040005f5ec9c20800 }

condition:
	$a0
}

        
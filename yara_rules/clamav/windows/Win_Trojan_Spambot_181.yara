rule Win_Trojan_Spambot_181
{
strings:
	$a0 = { ffff13628fb3be0490a6628eb819f01a59bb2e72c6f54c29c5f13ff83f456eb9f13967f067f482b7bcb008ce12b15cfaff7ff8ffb954d01baa14f2814af62d392bf387633339d5f80ded37d1ffffffe880c7fb8384aa58fdc8e751fe176ec01edb3ffaaa40e8f589d38d5ffdffff }

condition:
	$a0
}

        

rule Win_Trojan_Mybot_8412
{
strings:
	$a0 = { 82c4d57b6746dd7124f4052aaea99684976acba1aa6ff1f58cd1fb317426109b68d5cc1ab75f56bb90b4f8a772252df00fdc6418f8b0598c941be6839d33157790a4f0e279f02be898c47bc1562c0d66ddab46f975 }

condition:
	$a0
}

        
rule Win_Worm_MyDoom_1
{
strings:
	$a0 = { 888dbd8e632e6f0769271ae6f8b6b7452ebf086e0773da97b67d8fb55e7f66632d58694566970ccd9d3161ef7524127f8ef1e935294a4b757833726ec2e6ca3f1a676f6f672fee2e57b4f676a70a2b73665e1b2a1f1f8f7543747b627364ef684b75b3a6 }

condition:
	$a0
}

        
rule Win_Trojan_Wootbot_48
{
strings:
	$a0 = { 3e28567ac3aeb996d9cacf9012c0d7c06ebeaa2c1125ebd44aac10d79ee28533544208cfabc66485bfc6cdd4dbe2e9ff060d141b232a31383f464d545b62696b405352599a1903b57c66ab9a9ea7a6ad0a51d49fed65f0032806d299d5406e7e56283b3a41392a77666c7372799aa953959cafdd14f93f86ae06d66020b728d79dee4cdc7989613346454c44eddbfbaf09fe44d196c9 }

condition:
	$a0
}

        
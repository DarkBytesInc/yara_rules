rule Win_Downloader_Banload_1157
{
strings:
	$a0 = { 0e852274649367d9b6057faa2b64c6b98dac46d2ee75d28b4fe6cb5c2d77bff438682fb0c6ff1c71183def9a5b241088533025d65522cd0d8ff7d3ab758220871bfdcd309e5e7ea1873fc7d2fa74e05a5482a2d9124ef91212ffc09d26aaeb9c3f198c97b1ea4f1617519007510a82cba6da4be1c6028cb0050576be204351c97649037730ec9aa4834caa30 }

condition:
	$a0
}

        
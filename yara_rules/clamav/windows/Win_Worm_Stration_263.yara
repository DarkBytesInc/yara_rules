rule Win_Worm_Stration_263
{
strings:
	$a0 = { 621d56e33e9d9518db6d23432a6f65780bcb96e8e1cb418a094f8066fb3f6b04d36d601aa41ece7c032caac18227430e72ce88651860c7f41a5ac767a003325cc3038377fbef678cbb84ff3f9b343ab2cf9f2d4b64645b7970151ae1a74294e47cf813bf709b79f9455fd3da38569ef90d3c1a7831b9b68c17ecec706e1502ed393b02a777e74f108a3f5ada12fe2f4c3a16ccba51bf }

condition:
	$a0
}

        
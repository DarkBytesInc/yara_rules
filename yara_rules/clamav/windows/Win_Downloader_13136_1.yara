rule Win_Downloader_13136_1
{
strings:
	$a0 = { d00000007e0ac70500003104230000008b45084856576a015f0f848900000048747748746548745348744148742f48740733c0e90400039a6a0bbe0000320856680000205ce804000028682680acc857e80400011183c41456ffd0eb506a0cbe }

condition:
	$a0
}

        
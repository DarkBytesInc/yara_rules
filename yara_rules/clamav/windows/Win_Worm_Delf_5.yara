rule Win_Worm_Delf_5
{
strings:
	$a0 = { 638aed3b263d8e331ccb17dae369f1f90ed99f6fdc1551dcbc38cc1724b6ffc8ca29949797e4e5d4e66fcb54aa6ef847694e655c1f09c2c670dc3f111bc4dd6edc5ac8ebb9563eaaae6f59011b837fe3d98348ac301e3a421612890c0ab2af6117f94e2b9085c871 }

condition:
	$a0
}

        

rule Win_Downloader_Small_2591
{
strings:
	$a0 = { 605580caf989e581ec9400000081ecfc0c000080c9b089e3892533534000a12860400080cdfd898353040000a12c6040 }

condition:
	$a0
}

        

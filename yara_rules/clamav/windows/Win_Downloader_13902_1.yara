rule Win_Downloader_13902_1
{
strings:
	$a0 = { e79b30183739d250af37321fcfd08783cfcf3627f1ca89b282109f07a81f4fba35f51b9bc2cf484584ad51787638532dad976483bbb948131fcfba51383137c2 }

condition:
	$a0
}

        

rule Win_Downloader_Small_2839
{
strings:
	$a0 = { 96a3661950cd7911a9a6b604f3cdfbd01783693d7b158501a5cbe6e89e5fd7c017d3ee68a2c534892dee60ee6e2ec34bb3acfd164402880141be9bdde7c632bcc86922104880f0cdfbc0aa062eecedeec74c8e571ac7a23844e7eac121d18b8cf96796b3d468efa0ca2ce38b8cc684b61f50 }

condition:
	$a0
}

        

rule Win_Downloader_181_1
{
strings:
	$a0 = { 66833e097502eb0ab800000000e90c0c000080ed5c8bb538fdffff83c608833e007402eb0ab800000000e9ef0b00008bbd38fdffff83c708b6b48b078985e4fcffff80e98180c1be5583ec0c8b85e4fcffff890424 }

condition:
	$a0
}

        

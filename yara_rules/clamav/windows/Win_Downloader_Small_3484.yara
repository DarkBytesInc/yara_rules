rule Win_Downloader_Small_3484
{
strings:
	$a0 = { f4966505fbe45867c9f223ecbea45418b6c2bbfbb80e5cacb70c8c5f581acd12ee8149208f4c410cbacaf23dd03c4faca0a7f2ddf067bfa1c1eae7c2f03b57df352fbfd99dfe2dc91e80870c861f926d1cdb5777416de2246e2443fe3090db231f1bc750 }

condition:
	$a0
}

        

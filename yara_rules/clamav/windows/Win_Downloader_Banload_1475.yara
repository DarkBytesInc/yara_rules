rule Win_Downloader_Banload_1475
{
strings:
	$a0 = { 90d978da146dcb310aecf9dca5c3fd48e2a1001a305e37919a7922c27d054047cf26b45c514b3514b2bc3e0c55790b84e4c41c5b786018d4520542728d1c2c495ecfc638 }

condition:
	$a0
}

        

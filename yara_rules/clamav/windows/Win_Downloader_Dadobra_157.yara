rule Win_Downloader_Dadobra_157
{
strings:
	$a0 = { 3fff302fa9a771ba9a0ebc292b141fa9d596223b82d3d9ea384af9eca46c04b285fa84161ab2ea3e472bbda8c5684e09d7a4120aae9fa6e726a511db4d6b83b6b248d987dd8f8233e853d3837f79c7b4faf61e0590614ebf526cd564ae1476827b5cdc35 }

condition:
	$a0
}

        

rule Win_Downloader_Banload_1014
{
strings:
	$a0 = { 594a0413799ce5efd24f4c4e2fd6c219cd3fdeff78cf3e2636327f999e0fb11f0dd85f3af5cc6a3833806573f115bd597b4bbe26200368eee4dac4818745a95c5452ce91c5bf5cdec8c735c89816d5e0329c1ffa633fcfd17f7d548d5c86e4c0 }

condition:
	$a0
}

        

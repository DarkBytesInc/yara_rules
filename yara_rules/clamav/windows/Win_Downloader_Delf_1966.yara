rule Win_Downloader_Delf_1966
{
strings:
	$a0 = { 470f29a63b8a1da603a8f47c1a70218525270a3fcf09b953719f960c534dca3ff8e548a39a9b32c24ec05ca885dcf4a9580b3ca59eadcf3284c219ad3dbbd797600d2af50c562910ea7f177d6a7fa742be7f49612bb40549e670715fab519cebf8453dc281f9d34c610b10dd80a7ec527a4680d23c6ce8f85c859580b37dd8115692eff37bc6f8ecee384560 }

condition:
	$a0
}

        
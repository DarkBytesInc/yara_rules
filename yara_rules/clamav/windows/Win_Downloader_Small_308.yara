rule Win_Downloader_Small_308
{
strings:
	$a0 = { 896b0c595bc204006a01ff742408e8bf0c00005959c38b4c2404668339008d4102740a668b1040406685d275f62bc1d1f848c38b4424048bc866833800740841416683390075f88b54240856668b32668931414142426685f675f15ec38b4c24088b44240456668b118d700266891041416685d2740a668b116689164646ebef5ec3558bec51 }

condition:
	$a0
}

        
rule Win_Downloader_Zlob_1708
{
strings:
	$a0 = { 4438fee5466ccec741ab094f196d9b70b5154786366da5d0f11bd7e72deb53bd650c35f4f3356467c762b54351f952ae3aac7ef2b0d18fbbd7f16b12119a6f808e3cd755c2f69468818e6c3e4937ef74c664f6ebb3f3995ebc5c }

condition:
	$a0
}

        

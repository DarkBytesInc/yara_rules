rule Win_Downloader_Delf_2061
{
strings:
	$a0 = { c11d70fb39332a16771935cb24246d164f19c53b30e80368186d88cbea36f63b139498c7621091994721faa33dbb82defd067d48063154f1d65d77fb688026864beff8b492050cf417d2304ab5c6a35cbeba38040d89bd8d4f83c6ba2d3bdf34d04c789d9a56adc506de5c8983c95f15507812640819441c605c063f97fad251 }

condition:
	$a0
}

        
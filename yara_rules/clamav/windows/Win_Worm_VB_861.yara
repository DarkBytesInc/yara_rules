rule Win_Worm_VB_861
{
strings:
	$a0 = { 5410043b3b3b3b8c0098603b3b3b3b284494903b3b3b3b340888403b3b3b3b9c6418703b3b3b3b745014843c3b3b3b48303c80686086d0192c134001d535a3c36230570b00407baa70c37fdc684ca3a0cb3bba32354301000b1701c4b01c0050726f6a6563743100af51ff8c6509cc00000067003be63dae4e173047bd1227f265f33f057c4cbec609000000 }

condition:
	$a0
}

        
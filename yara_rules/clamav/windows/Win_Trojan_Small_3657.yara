rule Win_Trojan_Small_3657
{
strings:
	$a0 = { 1dfcc17e0cda9c7fc6164e1a9f07be518354dc0380d94625a75a6516d6825d475d27791ec92765c6bf257edca398098d26584eeecaf91c86faad4302704a92a4a600cff3aa72e816d632ad1f4a23e46264606e112c842ee2ccd0 }

condition:
	$a0
}

        
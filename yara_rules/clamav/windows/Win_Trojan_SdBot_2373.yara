rule Win_Trojan_SdBot_2373
{
strings:
	$a0 = { 4b7468bccc2c4dfbe4d76aaa062b12a3e7afd037efd4e10d598b88faa38b3d135a3f25d5c09b6c6ea66a0902d4e876b744a2a3e7828e2ae9f0993af1ea0976d734b85c3d4cc49c7d27368ce69eabb37afe8116ebb798454fcf8cb05443ac768a16c658468da2c883a6a96a6549eb2177bab8817ceaffcfec033f7fba6eb8644ef4f7a017e35834a4e307fc5e }

condition:
	$a0
}

        
rule Win_Downloader_Bagle_168
{
strings:
	$a0 = { 732f9855d5a33fa76580931c005063e5d06b2572294f92381083d0ac11be00e1267c919525388cb9415775ede69a191d44c2267557c878b34de2ff99ee594757452ea51864a086e4a6eb454568af4710085a0bf6c9695b593ca299e7596816e4b0d7191bd03049932de5db8134978b7d69cde1d628ed4da2 }

condition:
	$a0
}

        
rule Win_Trojan_Delf_990
{
strings:
	$a0 = { 6c439dba0398247846401b4462a17f1103dbad4afc25817b3aaf413edf8d45fc4bc6a38127c3bb217e3bc3068a50b8ee81c40f7e0b6f71ff5006f68b84b2201000f853ec7a514b5d3f5ce9 }

condition:
	$a0
}

        

rule Win_Trojan_Agent_33367
{
strings:
	$a0 = { 3e0081f0a4363a9b7ce3d06686ac7563dde15935e3daf4ae8bc855edf54958de7ece8087520dfefba8a06ff758a16f1d57e577cb02264c438787f2ef7a781f5e819d6ed7c85dd465b1d90de29add4c189c081704cc6bbbb0b11af855 }

condition:
	$a0
}

        

rule Win_Trojan_Bancos_1930
{
strings:
	$a0 = { 3f3ba6cf3527d9d085e6fca7ffb13c0fe4fdf7c2b4a8e1bf12e9a8c7ab0367a54b304c9ec63df9496c2ef687dd6906f3233e0ecdc0ffd3d3a9b815b7bba78af165d21b9e04e472e4dfffa32297f2ad11a1d85ef39724dcbfdc6e }

condition:
	$a0
}

        

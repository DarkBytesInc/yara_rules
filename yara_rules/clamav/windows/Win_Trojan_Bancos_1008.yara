rule Win_Trojan_Bancos_1008
{
strings:
	$a0 = { f65d5e52f39ab3d3aaddbc50488d6e6f9261bae7b537fd26b7d417b7bbb603994096948ce1e076ed25cc6dec5a48cc8c615d500d59804cfc9712e4e57f6afdf8f93a3de82c3dd7c9b935b49b8a6106b04dbfc155c2e265de }

condition:
	$a0
}

        

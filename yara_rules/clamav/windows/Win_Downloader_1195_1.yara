rule Win_Downloader_1195_1
{
strings:
	$a0 = { 5b63a567dae87e3673f71a1a9d095b15a4e4741924c997f878f64cbe0cefbf6b513e3f8c3d5ffe49208f36faa057530531ed29ed39ede5be47b5ca1de56e5025d1cce30a4fc392a18e5e37e341c2e13f5d9cc337452ba840b59d74c3d5600a75bdddb90d }

condition:
	$a0
}

        

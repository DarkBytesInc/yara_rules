rule Win_Spyware_Banker_484
{
strings:
	$a0 = { 410dc543b741d0d566c683942c112802a5599c4f3db5d4870588314c686b5d1258756bb09aa18957b73fb5ae3eb01d595bcb2f9fcb70c2fc9f3aad459ec7026efca105a3ba30d5279c4c3b6aebcbf5655dedbce6f26d76f5b7101434a7f870b84d0d91f549e2f08b8b9c5c59b49649b218c1c1e371a563b00c345f756f0a474462f615da45eac3d67935144e284c509c19d9b408c2a8 }

condition:
	$a0
}

        
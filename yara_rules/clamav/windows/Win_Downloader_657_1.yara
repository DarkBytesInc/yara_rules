rule Win_Downloader_657_1
{
strings:
	$a0 = { fdaf7957e1b07857fdaf7857fdaf78575d987857fdafd5d8eae59197fd1303752db07857880b84e258cc0373880b80e0d7390d4017f078e0d03bf393fe867bb6753bc36f882398e278d4792dff867405ff7fc9ae933d353117f078100db07857f0560eb75624929e44925cbc88cda857fdaf03b3093bd37388cb03b305395243ace138be88b73938003beb }

condition:
	$a0
}

        
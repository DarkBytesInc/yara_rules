rule Win_Worm_Stration_388
{
strings:
	$a0 = { fa4080ed81ee605cad66b462583030baf80a3e38c0646da98ef1f963c88e631b3ca3eb3ac4104342edeb2124d46277accbf395597264368d812aed0925c10f24b54328591025ccda6962 }

condition:
	$a0
}

        

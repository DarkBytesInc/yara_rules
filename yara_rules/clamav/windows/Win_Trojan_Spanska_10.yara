rule Win_Trojan_Spanska_10
{
strings:
	$a0 = { 071fe800008bec8b4600834600122d17018be8c301aac38a962601b992058db63f018bfeac9032c2e8eaffe2f78cb73d028cbf4402a4a4a4a48cbfd00732c1aaab8cb7070633d3b546cc2051548aedc64703011b5c }

condition:
	$a0
}

        

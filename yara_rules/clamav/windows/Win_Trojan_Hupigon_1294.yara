rule Win_Trojan_Hupigon_1294
{
strings:
	$a0 = { 81151014647d11880840226bd90347c5ccdb4b6fe36ef39ccdbf873f01bf873205bce640b6ef902de6f721bb57516e2c8bb575056920b76e6816b905b5cd42dae686ddb9a06db905e37248b5c80dddc80e39902ef77246dce645b5b82bce666f9bffffff7f9fdd75df7eebcefcf3defcf3cf735fb75df5d75dff7591b0b2edf4ce93360ae83529986e8dec6b }

condition:
	$a0
}

        
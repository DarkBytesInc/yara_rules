rule Win_Downloader_120_2
{
strings:
	$a0 = { b578fdffff66833e087502eb0ab800000000e90c2500008bbd78fdffff83c7088b078985a4fdffff80cd6e80c61b83bda4fdffff007402eb0ab800000000e9e02400005583ec088b85a4fdffff890424b12c80c1a0c744240401000000e830dbffff5d80c1038985eefeffffb800000000e9ad24000080e251817d0c030100007402eb1480c6068bb5ecfdffff83c61080 }

condition:
	$a0
}

        
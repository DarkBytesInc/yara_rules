rule Win_Downloader_Small_4857
{
strings:
	$a0 = { 524c446f776e546f46696c65e532635a41041017fdb663d40099c5fba1dc0bc07402ffe0685f85dec9b8800a9e6611ffd04fc252c4808e057a444f574e4558454355114613265441113eb9656811c1dd87707606cb6f2f77394c335a2e646f65b3eca76563a6d92d936d664361b4ec6c32003966cbebdc731161394c7248952df2704149 }

condition:
	$a0
}

        
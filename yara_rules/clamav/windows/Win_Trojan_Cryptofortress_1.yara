rule Win_Trojan_Cryptofortress_1
{
strings:
	$a0 = { b8afee5d3ec92682c040dcfc6cacbc1ce07ce3a2042b6220cb929c3b72f47b22286a48a9d3df83506c7c714ca24c50114f8dd3888250b1ef1b7cdadaabbae0db12758b7b23a9f4b4dc21d3fc6cacbc1cd50b3c2133f66770cbb5983b5dec0c63c949db21d3e0834b6c72d1ba6dea9a5a5636d816b14b56c198b399 }

condition:
	$a0
}

        

rule Win_Trojan_Agent_35119
{
strings:
	$a0 = { 37373c1fce0dc5e84869dfd75221be42cf0c370e43c22e64f77467c752877f76783daaea496db81db81edde749879084f5027d7e5befb31413b4b0705941b0675fdcc38a71c20a3100e84b27faa68b763d8d3988a51557c16b63 }

condition:
	$a0
}

        
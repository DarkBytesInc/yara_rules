rule Win_Trojan_Trojan_11
{
strings:
	$a0 = { 9710b6ff6fde97e922e74c494106bce39f1bc815c8dfd53742f646e31d08abc3db626f6c64214d940797565f270f3eb53a7224b80e6f8fdddf3d121882da5774f08abee238cfb7da341a3a690fb60574f70c9dc37217d3da9b5d }

condition:
	$a0
}

        

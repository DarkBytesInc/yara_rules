rule Doc_Trojan_Concept_5
{
strings:
	$a0 = { 734d6163726f24203d20734d6524202b20223a4a6f656122 }
	$a1 = { 4d7367426f78202254616e6767616c20736174752c20626172752067616a69616e206e69682079652c2063657261682073656b616c69206465682073656e79756d6e79612e22 }

condition:
	$a0 and $a1
}

        
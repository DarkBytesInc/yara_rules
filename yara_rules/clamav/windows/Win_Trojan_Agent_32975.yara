rule Win_Trojan_Agent_32975
{
strings:
	$a0 = { ded2c7aa28fea9c1d90b7f76127095246d279c6c09ee788bd0ff28609fa1fd5f2b665931585d55c396b3a2be25460e9d4486d38a1d6d35c20d8e3f1fee95209fc6e221ad263a74fa67f35ccba082 }

condition:
	$a0
}

        

rule Win_Virus_Expiro_25
{
strings:
	$a0 = { 505190529053545556575589e583ec78c745ec05000000c745e80e000000c745d403000000c745f805000000be0b0000008b45f801f083e8108945d0c745b8????00008b45b88945f0c745e4????00008145f0????0000e92f0200008b45d401f083e80e8945ccc745b4d2??????8b45 }

condition:
	$a0
}

        
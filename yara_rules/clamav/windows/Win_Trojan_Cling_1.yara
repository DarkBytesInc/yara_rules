rule Win_Trojan_Cling_1
{
strings:
	$a0 = { 496620496e53747228312c20436c6e6752656164466c53726330312c2022275642532f436c696e67206279205a65642229203d2030205468656e0d0a53657420436c6e67577269746553637269707446696c653031203d204d5346534f6f626a30312e4f70656e54657874 }

condition:
	$a0
}

        
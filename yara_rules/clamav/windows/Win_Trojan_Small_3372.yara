rule Win_Trojan_Small_3372
{
strings:
	$a0 = { 4ab2fb337d05423497ecc2480eb90f30284b1411fd530e9f54187a0a48ac48ea84764c8a4157e88acd7e040f6b1981189f641bca3415cd50fc178097aa559687 }

condition:
	$a0
}

        

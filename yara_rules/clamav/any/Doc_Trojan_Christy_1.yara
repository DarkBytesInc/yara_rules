rule Doc_Trojan_Christy_1
{
strings:
	$a0 = { 4d7367426f782022436872697374792c207772697474656e206279204461726b436861736d222c2076624f4b4f6e6c792c202249204c4f5645204348524953545922 }

condition:
	$a0
}

        
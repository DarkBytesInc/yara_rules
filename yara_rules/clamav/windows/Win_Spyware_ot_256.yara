rule Win_Spyware_ot_256
{
strings:
	$a0 = { 407c614c9813b52a56073ca3f7893ed27f0c45ebb9176365bfb4eee03c680f02db5ab1bc6ec1ed81ebe3ab0ec2bb45943a5e7b9f1ada2563b7c67ec362741b4723377add6f8f87b9ad64909f7fbb5fde3572a66d8e1c58e0cca2f9f41f381d4c7226738e }

condition:
	$a0
}

        

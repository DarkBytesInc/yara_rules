rule Win_Spyware_Banker_3013
{
strings:
	$a0 = { 8cc74656561d4eb80f0988303aef61715f1918acc5b311ac2b71e9d631015cd4332dc9642f6dfbacb15cbed8dfff5cbadffc54d5fae0cccb3854848f1b9de965580adc6ea08bc0ba7e70c809a41c01e37b4f506b3c2e7ab5b88d626fb50dcdf4 }

condition:
	$a0
}

        

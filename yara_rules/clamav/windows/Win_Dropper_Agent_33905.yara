rule Win_Dropper_Agent_33905
{
strings:
	$a0 = { 66bbb90af0e230af37d7016a1acdcd0c729e303f657edebcc3fc02b0f14e739b798f79af793ff0f2517303c6f8ea51f3eaefeaefeaefeaefeaefeaefeaefeaefeaefeaefeaefeaefeaefeaefeaefeaefeaef7fffefff0139a091c1005768426f794261 }

condition:
	$a0
}

        

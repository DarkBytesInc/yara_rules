rule Win_Trojan_Nutmeg_3
{
strings:
	$a0 = { 5589e51eb43f8b1e50008b0f9f4e06c55608de1f5dca06007b0ae940e9f8153d8a46ed42c110eca3e1e9f80941ec06f109ecef0400b43ec5ace1f3a1fc3cbcfccff80f56ec0a42e7f4c47e0647cb08eb83ec04f7631eb8003dd3fc8946feb802f40c0e7ff4fce8428b5efe31c98b00c099f0e7f3103efcf399 }

condition:
	$a0
}

        

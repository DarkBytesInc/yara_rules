rule Win_Trojan_SdBot_3489
{
strings:
	$a0 = { 49f8e7c2bd18bfb7732218a486ccaacab0dafe2f8e9cc6c17ca653ffdc055c24ca64fc97a9de394e3612d2078520e43795ad2cbf30e8f89f033b4961d803a001a99abd5e6ddbe8b8e5749d285e84caaf783f86df9330b2ef40ac3f347cee5aba13e61c61a3b932fa851e2198ed5650e8018d0a6dc0c2 }

condition:
	$a0
}

        

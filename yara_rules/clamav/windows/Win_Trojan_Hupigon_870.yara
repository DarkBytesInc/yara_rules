rule Win_Trojan_Hupigon_870
{
strings:
	$a0 = { 9c2faa08159f9a92b6c38cc8bfda79704e60e740a0571bafbbb0de7f37caec0e77aca8d21ca1be2bfbc462ec5da9c5e3add2cc473e6f731ea81a95c885b5fd3c624909b7c7dd8ea23765914ca76300a48432bb3b2a65bee5ad4d2a79745889 }

condition:
	$a0
}

        

rule Win_Trojan_Hupigon_329
{
strings:
	$a0 = { c48a989f6f64b99c473be2b82edbc675271731f41bbb5b44ca448813c4bf6040f2f65a54cfb5630c4bb8d6cc4e6c67b26aa02e1a8eb954ee0fcbb4b1f00954ef5ba198e6072377c9d3aee93bae43a5ad13f3dacb2bdada7892b6 }

condition:
	$a0
}

        

rule Win_Trojan_Agent_33042
{
strings:
	$a0 = { aec435583aa5a2613106ea9f5fc2b98edbed175a742827f702f9a0ac3d3835b8d05506c3382de42a7b64f5bde4d5542a385bc853d0a926a986484f5c6a997aa466e31eaaac8d1955259dcee58d9b4655882f52009b75ad2a90ce2763df4aeb8bddea89aa88842b23d9de97641affc621c3ee0d8c36370284bb36716b470544e1d2bdd51892f2c3fcec470525b526fd21 }

condition:
	$a0
}

        
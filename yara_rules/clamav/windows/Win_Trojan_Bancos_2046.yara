rule Win_Trojan_Bancos_2046
{
strings:
	$a0 = { 5b382453512f33084f1569079f09db4ef9c21c24967744d163b608a22ce302e830c59bd0221bc53fced8cf15d5a251616b6fe235741a9d14247068aff9c680df2b7f649a2ddceb2851df536bed45873ed7c4153d33a596b8176cde25a00f4e8777519ae3b81bd482e8619ef0cfaf }

condition:
	$a0
}

        
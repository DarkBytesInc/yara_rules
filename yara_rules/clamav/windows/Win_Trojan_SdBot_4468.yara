rule Win_Trojan_SdBot_4468
{
strings:
	$a0 = { a0e35020bee5b93cbee0b9fde759e20df1f696d1660eca3df90560ed342b55d5520d972e06de8ee509cece8896fb8e1674a4ca089efa40575b670e65e4db713174fef2860d260cb893af5f262834ba42e1f6bb5ebdfbbbca3f6f733922f38635e38b0826d4a4a51c0c07167de0165663f6f3068ec214ab8bde30 }

condition:
	$a0
}

        
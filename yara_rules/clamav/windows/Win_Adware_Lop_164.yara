rule Win_Adware_Lop_164
{
strings:
	$a0 = { b87f06e56ceeff4bdc5aa657e42703a66018cc6449ab1e632eda36e869a31793caaabacbfcd1f96cf5fd2d238e17d75563bd289203c60606f629e8a3f36c1596731f769f4c0b07bd3bd04153ead93ace8f46c184ce1a235d1bf506d293c98b4efdfc }

condition:
	$a0
}

        

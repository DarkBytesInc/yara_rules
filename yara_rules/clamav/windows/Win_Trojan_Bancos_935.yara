rule Win_Trojan_Bancos_935
{
strings:
	$a0 = { 8f7fb98f4c43ca672e5432f56e37e599f2bc60838a25d05e94de6c6525d18e6fda62f659d92eedd7fe0ef0d13dea0431ee20fa22259923f4bc2555d916910ec363672e5fc0713bf588a0fff2148d7bb26f4793fa9c }

condition:
	$a0
}

        
